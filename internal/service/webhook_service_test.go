package service

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/ssrf"
	"gorm.io/gorm"
)

// memWebhookRepo is an in-memory WebhookRepository for service tests.
type memWebhookRepo struct {
	mu         sync.Mutex
	nextSubID  uint
	nextDelID  uint
	subs       map[uint]model.WebhookSubscription
	deliveries map[uint]model.WebhookDelivery
}

func newMemWebhookRepo() *memWebhookRepo {
	return &memWebhookRepo{
		subs:       map[uint]model.WebhookSubscription{},
		deliveries: map[uint]model.WebhookDelivery{},
	}
}

func (r *memWebhookRepo) CreateSubscription(_ context.Context, sub *model.WebhookSubscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextSubID++
	sub.ID = r.nextSubID
	sub.CreatedAt = time.Now()
	sub.UpdatedAt = sub.CreatedAt
	r.subs[sub.ID] = *sub
	return nil
}

func (r *memWebhookRepo) UpdateSubscription(_ context.Context, sub *model.WebhookSubscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.subs[sub.ID]; !ok {
		return gorm.ErrRecordNotFound
	}
	sub.UpdatedAt = time.Now()
	r.subs[sub.ID] = *sub
	return nil
}

func (r *memWebhookRepo) DeleteSubscription(_ context.Context, id uint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.subs, id)
	for did, d := range r.deliveries {
		if d.SubscriptionID == id {
			delete(r.deliveries, did)
		}
	}
	return nil
}

func (r *memWebhookRepo) FindSubscriptionByID(_ context.Context, id uint) (*model.WebhookSubscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sub, ok := r.subs[id]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return &sub, nil
}

func (r *memWebhookRepo) ListSubscriptions(_ context.Context, appID *uint) ([]model.WebhookSubscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.WebhookSubscription
	for _, s := range r.subs {
		if appID != nil && (s.AppID == nil || *s.AppID != *appID) {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func (r *memWebhookRepo) ListActiveSubscriptions(_ context.Context) ([]model.WebhookSubscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.WebhookSubscription
	for _, s := range r.subs {
		if s.Active {
			out = append(out, s)
		}
	}
	return out, nil
}

func (r *memWebhookRepo) ListDeliveries(_ context.Context, subscriptionID *uint, status string, page, pageSize int) ([]model.WebhookDelivery, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.WebhookDelivery
	for _, d := range r.deliveries {
		if subscriptionID != nil && d.SubscriptionID != *subscriptionID {
			continue
		}
		if status != "" && d.Status != status {
			continue
		}
		out = append(out, d)
	}
	return out, int64(len(out)), nil
}

func (r *memWebhookRepo) FindDeliveryByID(_ context.Context, id uint) (*model.WebhookDelivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deliveries[id]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return &d, nil
}

func (r *memWebhookRepo) RequeueDelivery(_ context.Context, id uint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deliveries[id]
	if !ok {
		return gorm.ErrRecordNotFound
	}
	d.Status = model.WebhookDeliveryPending
	d.Attempts = 0
	d.NextAttemptAt = time.Now()
	d.LastError = ""
	r.deliveries[id] = d
	return nil
}

// ClaimDue mirrors the SQL claim: pending, due now, oldest first, and the
// claimed rows get their next attempt pushed out by the lease.
func (r *memWebhookRepo) ClaimDue(_ context.Context, limit int, leaseUntil time.Time) ([]model.WebhookDelivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit <= 0 {
		limit = 20
	}

	var due []model.WebhookDelivery
	now := time.Now()
	for _, d := range r.deliveries {
		if d.Status == model.WebhookDeliveryPending && !d.NextAttemptAt.After(now) {
			due = append(due, d)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].NextAttemptAt.Before(due[j].NextAttemptAt) })
	if len(due) > limit {
		due = due[:limit]
	}
	for _, d := range due {
		row := r.deliveries[d.ID]
		row.NextAttemptAt = leaseUntil
		r.deliveries[d.ID] = row
	}
	return due, nil
}

func (r *memWebhookRepo) MarkDelivered(_ context.Context, id uint, statusCode int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deliveries[id]
	if !ok {
		return gorm.ErrRecordNotFound
	}
	now := time.Now()
	d.Status = model.WebhookDeliveryDelivered
	d.LastStatusCode = statusCode
	d.LastError = ""
	d.DeliveredAt = &now
	d.Attempts++
	r.deliveries[id] = d
	return nil
}

func (r *memWebhookRepo) MarkFailed(_ context.Context, id uint, statusCode int, reason string, nextAttempt time.Time, dead bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deliveries[id]
	if !ok {
		return gorm.ErrRecordNotFound
	}
	if len(reason) > repository.MaxLastErrorLen {
		reason = reason[:repository.MaxLastErrorLen]
	}
	d.Status = model.WebhookDeliveryPending
	if dead {
		d.Status = model.WebhookDeliveryDead
	}
	d.LastStatusCode = statusCode
	d.LastError = reason
	d.NextAttemptAt = nextAttempt
	d.Attempts++
	r.deliveries[id] = d
	return nil
}

func (r *memWebhookRepo) CountByStatus(_ context.Context) (map[string]int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]int64{}
	for _, d := range r.deliveries {
		out[d.Status]++
	}
	return out, nil
}

func (r *memWebhookRepo) DeleteDeliveredOlderThan(_ context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, d := range r.deliveries {
		if d.Status == model.WebhookDeliveryDelivered && d.UpdatedAt.Before(before) {
			delete(r.deliveries, id)
			n++
		}
	}
	return n, nil
}

// addDelivery seeds the outbox for the delivery-side tests.
func (r *memWebhookRepo) addDelivery(subID uint, status string) uint {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextDelID++
	r.deliveries[r.nextDelID] = model.WebhookDelivery{
		ID: r.nextDelID, SubscriptionID: subID, Status: status, Attempts: 3,
		LastError: "connection refused", UpdatedAt: time.Now(),
	}
	return r.nextDelID
}

// stubResolver makes the SSRF guard hermetic: hooks.example.com answers with a
// public address, everything else fails to resolve. Production always uses the
// real resolver — this is only so the tests need no network.
func stubResolver(t *testing.T) {
	t.Helper()
	original := ssrf.Resolver
	ssrf.Resolver = func(host string) ([]net.IP, error) {
		switch host {
		case "hooks.example.com", "siem.example.com":
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		case "internal.example.com":
			// A public name that answers with a private address — the DNS
			// rebinding shape.
			return []net.IP{net.ParseIP("10.0.0.7")}, nil
		case "mixed.example.com":
			// One public answer and one private: the target is unsafe.
			return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")}, nil
		default:
			return nil, errors.New("no such host")
		}
	}
	t.Cleanup(func() { ssrf.Resolver = original })
}

func newWebhookSvc(t *testing.T) (WebhookService, *memWebhookRepo) {
	t.Helper()
	stubResolver(t)
	repo := newMemWebhookRepo()
	// A 32-byte key, as SECRET_KEY_BASE must be in production.
	return NewWebhookService(repo, []byte(strings.Repeat("k", 32))), repo
}

func TestWebhookCreate_ReturnsSecretOnceAndStoresItEncrypted(t *testing.T) {
	svc, repo := newWebhookSvc(t)

	sub, secret, err := svc.Create(context.Background(), dto.CreateWebhookRequest{
		Name:       "SIEM",
		URL:        "https://hooks.example.com/socrate",
		EventTypes: []string{"login.failed", "user.created"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !strings.HasPrefix(secret, "whsec_") || len(secret) < 40 {
		t.Errorf("secret looks wrong: %q", secret)
	}
	stored := repo.subs[sub.ID]
	if stored.SecretEnc == "" {
		t.Fatal("no secret stored")
	}
	if strings.Contains(stored.SecretEnc, secret) {
		t.Fatal("the signing secret is stored in plaintext")
	}

	// The service can recover it for the dispatcher.
	back, err := svc.Secret(sub)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if back != secret {
		t.Fatalf("decrypted secret = %q, want %q", back, secret)
	}

	// The filter is normalized and sorted.
	if len(sub.EventTypes) != 2 || sub.EventTypes[0] != "login.failed" {
		t.Errorf("event filter = %v, want sorted [login.failed user.created]", sub.EventTypes)
	}
}

// The SSRF guard runs at registration, so an unsafe target never reaches the
// outbox in the first place.
func TestWebhookCreate_RefusesUnsafeTargets(t *testing.T) {
	svc, _ := newWebhookSvc(t)

	unsafe := []string{
		"http://hooks.example.com/",         // not https
		"https://127.0.0.1/x",               // loopback — the admin API lives here
		"https://localhost:8081/api/admin/", // same, by name
		"https://169.254.169.254/latest/",   // cloud metadata
		"https://10.1.2.3/hook",             // RFC 1918
		"https://user:pw@hooks.example.com/",
		"",
	}
	for _, raw := range unsafe {
		_, _, err := svc.Create(context.Background(), dto.CreateWebhookRequest{
			Name: "bad", URL: raw, EventTypes: []string{"*"},
		}, 1)
		if !errors.Is(err, ErrWebhookInvalidURL) {
			t.Errorf("Create(%q) = %v, want ErrWebhookInvalidURL", raw, err)
		}
	}
}

// A perfectly ordinary hostname that *resolves* to a private address is
// refused — the check is on the answer, not on how the target is spelled. A
// host whose answers are mixed is refused too: one private answer in a
// round-robin set is enough to make the target unsafe.
func TestWebhookCreate_RefusesPrivateResolution(t *testing.T) {
	svc, _ := newWebhookSvc(t)

	for _, raw := range []string{
		"https://internal.example.com/hook",
		"https://mixed.example.com/hook",
	} {
		_, _, err := svc.Create(context.Background(), dto.CreateWebhookRequest{
			Name: "rebind", URL: raw, EventTypes: []string{"*"},
		}, 1)
		if !errors.Is(err, ErrWebhookInvalidURL) {
			t.Errorf("Create(%q) = %v, want ErrWebhookInvalidURL", raw, err)
		}
	}
}

// A filter naming an event outside the catalogue is refused, so a typo cannot
// produce a subscription that silently never fires.
func TestWebhookCreate_RefusesUnknownEvents(t *testing.T) {
	svc, _ := newWebhookSvc(t)

	_, _, err := svc.Create(context.Background(), dto.CreateWebhookRequest{
		Name: "typo", URL: "https://hooks.example.com/", EventTypes: []string{"user.craeted"},
	}, 1)
	if !errors.Is(err, ErrWebhookInvalidEvent) {
		t.Errorf("unknown event: err = %v, want ErrWebhookInvalidEvent", err)
	}

	_, _, err = svc.Create(context.Background(), dto.CreateWebhookRequest{
		Name: "empty", URL: "https://hooks.example.com/", EventTypes: nil,
	}, 1)
	if !errors.Is(err, ErrWebhookNoEvents) {
		t.Errorf("empty filter: err = %v, want ErrWebhookNoEvents", err)
	}
}

// Without SECRET_KEY_BASE there is nowhere safe to keep a signing secret, so
// creation is refused rather than storing one in the clear.
func TestWebhookCreate_RefusedWithoutSecretKey(t *testing.T) {
	stubResolver(t)
	svc := NewWebhookService(newMemWebhookRepo(), nil)
	_, _, err := svc.Create(context.Background(), dto.CreateWebhookRequest{
		Name: "x", URL: "https://hooks.example.com/", EventTypes: []string{"*"},
	}, 1)
	if !errors.Is(err, ErrWebhookNoSecretKey) {
		t.Fatalf("err = %v, want ErrWebhookNoSecretKey", err)
	}
}

func TestWebhookUpdate_ValidatesAndRefreshesCache(t *testing.T) {
	svc, _ := newWebhookSvc(t)
	sub, _, err := svc.Create(context.Background(), dto.CreateWebhookRequest{
		Name: "SIEM", URL: "https://hooks.example.com/a", EventTypes: []string{"*"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(svc.Subscriptions()) != 1 {
		t.Fatalf("routing cache has %d subscriptions after create, want 1", len(svc.Subscriptions()))
	}

	// An unsafe new URL is refused and the stored target is untouched.
	bad := "https://127.0.0.1/x"
	if _, err := svc.Update(context.Background(), sub.ID, dto.UpdateWebhookRequest{URL: &bad}); !errors.Is(err, ErrWebhookInvalidURL) {
		t.Fatalf("Update with a loopback URL: err = %v, want ErrWebhookInvalidURL", err)
	}
	current, err := svc.GetByID(context.Background(), sub.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if current.URL != "https://hooks.example.com/a" {
		t.Fatalf("URL changed despite the refusal: %q", current.URL)
	}

	// Deactivating removes it from the routing cache, so events stop being
	// enqueued immediately rather than at the next refresh tick.
	off := false
	if _, err := svc.Update(context.Background(), sub.ID, dto.UpdateWebhookRequest{Active: &off}); err != nil {
		t.Fatalf("Update (deactivate): %v", err)
	}
	if len(svc.Subscriptions()) != 0 {
		t.Fatalf("routing cache still holds %d subscriptions after deactivation", len(svc.Subscriptions()))
	}
}

func TestWebhookRotateSecret_IssuesANewOne(t *testing.T) {
	svc, _ := newWebhookSvc(t)
	sub, first, err := svc.Create(context.Background(), dto.CreateWebhookRequest{
		Name: "SIEM", URL: "https://hooks.example.com/", EventTypes: []string{"*"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rotated, second, err := svc.RotateSecret(context.Background(), sub.ID)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if second == first {
		t.Fatal("rotation returned the same secret")
	}
	back, err := svc.Secret(rotated)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if back != second {
		t.Fatalf("stored secret = %q, want the rotated one", back)
	}
}

func TestWebhookDelete_RemovesSubscriptionAndDeliveries(t *testing.T) {
	svc, repo := newWebhookSvc(t)
	sub, _, err := svc.Create(context.Background(), dto.CreateWebhookRequest{
		Name: "SIEM", URL: "https://hooks.example.com/", EventTypes: []string{"*"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	repo.addDelivery(sub.ID, model.WebhookDeliveryPending)

	if err := svc.Delete(context.Background(), sub.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.GetByID(context.Background(), sub.ID); !errors.Is(err, ErrWebhookNotFound) {
		t.Fatalf("GetByID after delete = %v, want ErrWebhookNotFound", err)
	}
	if len(repo.deliveries) != 0 {
		t.Fatalf("%d deliveries survived the subscription", len(repo.deliveries))
	}
	if len(svc.Subscriptions()) != 0 {
		t.Fatal("the deleted subscription is still in the routing cache")
	}
}

func TestWebhookRequeueDelivery(t *testing.T) {
	svc, repo := newWebhookSvc(t)
	id := repo.addDelivery(1, model.WebhookDeliveryDead)

	if err := svc.RequeueDelivery(context.Background(), id); err != nil {
		t.Fatalf("RequeueDelivery: %v", err)
	}
	d := repo.deliveries[id]
	if d.Status != model.WebhookDeliveryPending || d.Attempts != 0 || d.LastError != "" {
		t.Fatalf("requeued delivery = %+v, want pending with a clean slate", d)
	}

	if err := svc.RequeueDelivery(context.Background(), 9999); !errors.Is(err, ErrDeliveryNotFound) {
		t.Fatalf("requeue of a missing delivery = %v, want ErrDeliveryNotFound", err)
	}
}

func TestWebhookGetByID_NotFound(t *testing.T) {
	svc, _ := newWebhookSvc(t)
	if _, err := svc.GetByID(context.Background(), 404); !errors.Is(err, ErrWebhookNotFound) {
		t.Fatalf("err = %v, want ErrWebhookNotFound", err)
	}
}
