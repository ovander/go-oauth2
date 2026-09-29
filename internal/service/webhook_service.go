package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/internal/shared/ssrf"
	"github.com/ovander/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// Webhook service errors.
var (
	ErrWebhookNotFound     = errors.New("webhook subscription not found")
	ErrWebhookInvalidURL   = errors.New("invalid webhook URL")
	ErrWebhookInvalidEvent = errors.New("unknown webhook event type")
	ErrWebhookNoEvents     = errors.New("webhook subscription must name at least one event")
	ErrWebhookNoSecretKey  = errors.New("webhook secrets require SECRET_KEY_BASE to be configured")
	ErrDeliveryNotFound    = errors.New("webhook delivery not found")
)

// MaxWebhookSubscriptions bounds how many targets can be registered. Each
// subscription multiplies every audited event into another outbox row, so this
// is a guard on write amplification as much as on tidiness.
const MaxWebhookSubscriptions = 50

// webhookSecretBytes is the entropy of a generated signing secret.
const webhookSecretBytes = 32

// WebhookService manages delivery targets and the routing cache the outbox
// producer consults on the audit write path.
type WebhookService interface {
	List(ctx context.Context, appID *uint) ([]model.WebhookSubscription, error)
	GetByID(ctx context.Context, id uint) (*model.WebhookSubscription, error)
	// Create registers a target and returns the signing secret in plaintext —
	// the only time it is ever readable.
	Create(ctx context.Context, req dto.CreateWebhookRequest, createdBy uint) (*model.WebhookSubscription, string, error)
	Update(ctx context.Context, id uint, req dto.UpdateWebhookRequest) (*model.WebhookSubscription, error)
	Delete(ctx context.Context, id uint) error
	// RotateSecret issues a new signing secret, returned once.
	RotateSecret(ctx context.Context, id uint) (*model.WebhookSubscription, string, error)

	// Deliveries
	ListDeliveries(ctx context.Context, subscriptionID *uint, status string, page, pageSize int) ([]model.WebhookDelivery, int64, error)
	RequeueDelivery(ctx context.Context, id uint) error
	DeliveryStats(ctx context.Context) (map[string]int64, error)

	// Secret returns a subscription's signing secret in plaintext, for the
	// dispatcher. Never exposed through the API.
	Secret(sub *model.WebhookSubscription) (string, error)

	// Subscriptions returns the cached active subscriptions. It is called on the
	// audit write path, so it must not touch the database.
	Subscriptions() []model.WebhookSubscription
	// RefreshCache reloads the routing cache from the database.
	RefreshCache(ctx context.Context) error
	// StartCacheRefresh keeps the routing cache warm on a timer and returns a
	// stop function. A second instance's writes reach this one within one tick.
	StartCacheRefresh(interval time.Duration) func()
}

type webhookService struct {
	repo repository.WebhookRepository
	// secretKey encrypts subscription secrets at rest (AES-GCM, the same helper
	// as TOTP secrets). Empty disables webhook creation entirely rather than
	// storing a secret in the clear.
	secretKey []byte

	mu     sync.RWMutex
	cached []model.WebhookSubscription
}

// NewWebhookService creates the webhook service. secretKey is SECRET_KEY_BASE;
// an empty key leaves the service usable for reads but refuses to create a
// subscription, because that would mean persisting a signing secret in
// plaintext.
func NewWebhookService(repo repository.WebhookRepository, secretKey []byte) WebhookService {
	logger.WithFields(logger.Fields{
		"service": "webhook",
	}).Debug("✅ Webhook service initialized")
	return &webhookService{repo: repo, secretKey: secretKey}
}

func (s *webhookService) List(ctx context.Context, appID *uint) ([]model.WebhookSubscription, error) {
	return s.repo.ListSubscriptions(ctx, appID)
}

func (s *webhookService) GetByID(ctx context.Context, id uint) (*model.WebhookSubscription, error) {
	sub, err := s.repo.FindSubscriptionByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrWebhookNotFound
		}
		return nil, err
	}
	return sub, nil
}

func (s *webhookService) Create(ctx context.Context, req dto.CreateWebhookRequest, createdBy uint) (*model.WebhookSubscription, string, error) {
	if len(s.secretKey) == 0 {
		return nil, "", ErrWebhookNoSecretKey
	}

	events, err := validateEventFilter(req.EventTypes)
	if err != nil {
		return nil, "", err
	}
	if err := validateWebhookURL(req.URL); err != nil {
		return nil, "", err
	}

	existing, err := s.repo.ListSubscriptions(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	if len(existing) >= MaxWebhookSubscriptions {
		return nil, "", fmt.Errorf("at most %d webhook subscriptions may be registered", MaxWebhookSubscriptions)
	}

	secret, err := generateWebhookSecret()
	if err != nil {
		return nil, "", err
	}
	enc, err := auth.EncryptSecret(s.secretKey, secret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt the webhook secret: %w", err)
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "webhook"
	}

	sub := &model.WebhookSubscription{
		AppID:      req.AppID,
		Name:       name,
		URL:        strings.TrimSpace(req.URL),
		SecretEnc:  enc,
		EventTypes: model.StringArray(events),
		Active:     true,
		CreatedBy:  &createdBy,
	}
	if req.Active != nil {
		sub.Active = *req.Active
	}

	if err := s.repo.CreateSubscription(ctx, sub); err != nil {
		return nil, "", err
	}
	s.invalidate(ctx)

	return sub, secret, nil
}

func (s *webhookService) Update(ctx context.Context, id uint, req dto.UpdateWebhookRequest) (*model.WebhookSubscription, error) {
	sub, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		sub.Name = strings.TrimSpace(*req.Name)
	}
	if req.URL != nil {
		if err := validateWebhookURL(*req.URL); err != nil {
			return nil, err
		}
		sub.URL = strings.TrimSpace(*req.URL)
	}
	if req.EventTypes != nil {
		events, err := validateEventFilter(*req.EventTypes)
		if err != nil {
			return nil, err
		}
		sub.EventTypes = model.StringArray(events)
	}
	if req.Active != nil {
		sub.Active = *req.Active
	}

	if err := s.repo.UpdateSubscription(ctx, sub); err != nil {
		return nil, err
	}
	s.invalidate(ctx)
	return sub, nil
}

func (s *webhookService) Delete(ctx context.Context, id uint) error {
	if _, err := s.GetByID(ctx, id); err != nil {
		return err
	}
	if err := s.repo.DeleteSubscription(ctx, id); err != nil {
		return err
	}
	s.invalidate(ctx)
	return nil
}

func (s *webhookService) RotateSecret(ctx context.Context, id uint) (*model.WebhookSubscription, string, error) {
	if len(s.secretKey) == 0 {
		return nil, "", ErrWebhookNoSecretKey
	}
	sub, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, "", err
	}

	secret, err := generateWebhookSecret()
	if err != nil {
		return nil, "", err
	}
	enc, err := auth.EncryptSecret(s.secretKey, secret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt the webhook secret: %w", err)
	}

	sub.SecretEnc = enc
	if err := s.repo.UpdateSubscription(ctx, sub); err != nil {
		return nil, "", err
	}
	s.invalidate(ctx)
	return sub, secret, nil
}

func (s *webhookService) ListDeliveries(ctx context.Context, subscriptionID *uint, status string, page, pageSize int) ([]model.WebhookDelivery, int64, error) {
	return s.repo.ListDeliveries(ctx, subscriptionID, status, page, pageSize)
}

func (s *webhookService) RequeueDelivery(ctx context.Context, id uint) error {
	if _, err := s.repo.FindDeliveryByID(ctx, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrDeliveryNotFound
		}
		return err
	}
	return s.repo.RequeueDelivery(ctx, id)
}

func (s *webhookService) DeliveryStats(ctx context.Context) (map[string]int64, error) {
	return s.repo.CountByStatus(ctx)
}

func (s *webhookService) Secret(sub *model.WebhookSubscription) (string, error) {
	if sub == nil {
		return "", ErrWebhookNotFound
	}
	if len(s.secretKey) == 0 {
		return "", ErrWebhookNoSecretKey
	}
	return auth.DecryptSecret(s.secretKey, sub.SecretEnc)
}

func (s *webhookService) Subscriptions() []model.WebhookSubscription {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cached
}

func (s *webhookService) RefreshCache(ctx context.Context) error {
	subs, err := s.repo.ListActiveSubscriptions(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cached = subs
	s.mu.Unlock()
	return nil
}

func (s *webhookService) StartCacheRefresh(interval time.Duration) func() {
	if interval <= 0 {
		interval = time.Minute
	}
	// Load once up front so the first audited event after boot is routed.
	if err := s.RefreshCache(context.Background()); err != nil {
		logger.WithFields(logger.Fields{"error": err.Error()}).
			Warn("A3: initial webhook subscription load failed; retrying on the next tick")
	}

	stop := make(chan struct{})
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := s.RefreshCache(context.Background()); err != nil {
					logger.WithFields(logger.Fields{"error": err.Error()}).
						Warn("A3: webhook subscription refresh failed")
				}
			}
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(stop) }) }
}

// invalidate reloads the routing cache after a local write, so an operator's
// change takes effect on this instance immediately rather than at the next tick.
func (s *webhookService) invalidate(ctx context.Context) {
	if err := s.RefreshCache(ctx); err != nil {
		logger.WithFields(logger.Fields{"error": err.Error()}).
			Warn("A3: webhook subscription cache refresh failed after a write")
	}
}

// validateWebhookURL applies the SSRF guard at registration time. The same
// check runs again at connect time, because DNS can change in between.
func validateWebhookURL(raw string) error {
	if _, err := ssrf.ValidateURL(raw); err != nil {
		return fmt.Errorf("%w: %s", ErrWebhookInvalidURL, err)
	}
	return nil
}

// validateEventFilter normalizes a filter and refuses any name outside the
// catalogue, so a typo is caught at registration rather than producing a
// subscription that silently never fires.
func validateEventFilter(events []string) ([]string, error) {
	normalized := model.NormalizeEventFilter(events)
	if len(normalized) == 0 {
		return nil, ErrWebhookNoEvents
	}
	for _, e := range normalized {
		if e == model.WebhookEventWildcard {
			continue
		}
		if !model.IsKnownWebhookEvent(e) {
			return nil, fmt.Errorf("%w: %s", ErrWebhookInvalidEvent, e)
		}
	}
	return normalized, nil
}

func generateWebhookSecret() (string, error) {
	buf := make([]byte, webhookSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate a webhook secret: %w", err)
	}
	return "whsec_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
