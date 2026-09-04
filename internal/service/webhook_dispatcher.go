package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/ssrf"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// Dispatcher defaults. Each is overridable from config.
const (
	// DefaultMaxAttempts is how many times a delivery is tried before it is
	// dead-lettered. With the backoff below that spans roughly 20 minutes,
	// which covers a target's routine restart without holding a row forever.
	DefaultMaxAttempts = 6
	// DefaultPollInterval is how often a dispatcher looks for due deliveries.
	DefaultPollInterval = 10 * time.Second
	// DefaultBatchSize is how many deliveries one poll claims.
	DefaultBatchSize = 20
	// DefaultSendTimeout bounds a single delivery attempt.
	DefaultSendTimeout = 5 * time.Second
	// maxResponseBytes is how much of a target's response body is read before
	// the rest is discarded. The body is not used for anything — it is drained
	// only so the connection can be closed cleanly — so this is deliberately
	// small: a subscriber must not be able to feed the dispatcher a large body.
	maxResponseBytes = 4 << 10
	// backoffCap bounds the exponential backoff.
	backoffCap = 15 * time.Minute
)

// SignatureHeader carries the HMAC. Format: `t=<unix>,v1=<hex>`, where the MAC
// is HMAC-SHA256 over `<t>.<raw body>` keyed by the subscription secret.
//
// The timestamp is inside the signed material on purpose: signing the body
// alone would let anyone who captures a delivery replay it forever. A verifier
// should reject a timestamp outside its tolerance *and* compare the MAC in
// constant time.
const (
	SignatureHeader  = "X-Socrate-Signature"
	EventHeader      = "X-Socrate-Event"
	DeliveryHeader   = "X-Socrate-Delivery"
	AttemptHeader    = "X-Socrate-Attempt"
	SignatureVersion = "v1"
)

// WebhookDispatcher drains the delivery outbox: claim, sign, send, retry.
type WebhookDispatcher struct {
	repo   repository.WebhookRepository
	secret func(sub *model.WebhookSubscription) (string, error)
	subs   func(ctx context.Context, id uint) (*model.WebhookSubscription, error)
	client *http.Client

	maxAttempts int
	batchSize   int
	poll        time.Duration
	timeout     time.Duration
}

// DispatcherConfig configures the dispatcher; zero values take the defaults.
type DispatcherConfig struct {
	MaxAttempts  int
	BatchSize    int
	PollInterval time.Duration
	SendTimeout  time.Duration
}

// NewWebhookDispatcher builds a dispatcher over the outbox. The svc supplies
// subscription lookup and secret decryption; the HTTP client is the SSRF-guarded
// one, which re-checks the resolved address at connect time.
func NewWebhookDispatcher(repo repository.WebhookRepository, svc WebhookService, cfg DispatcherConfig) *WebhookDispatcher {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.SendTimeout <= 0 {
		cfg.SendTimeout = DefaultSendTimeout
	}

	return &WebhookDispatcher{
		repo:        repo,
		secret:      svc.Secret,
		subs:        svc.GetByID,
		client:      ssrf.NewHTTPClient(cfg.SendTimeout),
		maxAttempts: cfg.MaxAttempts,
		batchSize:   cfg.BatchSize,
		poll:        cfg.PollInterval,
		timeout:     cfg.SendTimeout,
	}
}

// Start runs the dispatch loop until the returned stop function is called.
func (d *WebhookDispatcher) Start() func() {
	stop := make(chan struct{})
	ticker := time.NewTicker(d.poll)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), d.poll+d.timeout*2)
				if n, err := d.DispatchOnce(ctx); err != nil {
					logger.WithFields(logger.Fields{"error": err.Error()}).
						Warn("A3: webhook dispatch pass failed")
				} else if n > 0 {
					logger.WithFields(logger.Fields{"deliveries": n}).
						Debug("A3: webhook dispatch pass complete")
				}
				cancel()
			}
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(stop) }) }
}

// DispatchOnce claims one batch and attempts each delivery. It returns how many
// were attempted. Exported so an operator tool — or a test — can run a single
// pass deterministically.
func (d *WebhookDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	// The lease keeps a claimed row from being re-claimed while in flight. If
	// this process dies, the row becomes due again once the lease expires.
	lease := time.Now().Add(d.timeout*2 + 30*time.Second)
	batch, err := d.repo.ClaimDue(ctx, d.batchSize, lease)
	if err != nil {
		return 0, fmt.Errorf("claiming due deliveries: %w", err)
	}

	for i := range batch {
		select {
		case <-ctx.Done():
			return i, ctx.Err()
		default:
		}
		d.attempt(ctx, &batch[i])
	}
	return len(batch), nil
}

// attempt makes one delivery attempt and records the outcome.
func (d *WebhookDispatcher) attempt(ctx context.Context, delivery *model.WebhookDelivery) {
	sub, err := d.subs(ctx, delivery.SubscriptionID)
	if err != nil {
		// The subscription is gone. Nothing will ever deliver this row, so
		// dead-letter it rather than retrying forever.
		d.fail(ctx, delivery, 0, fmt.Sprintf("subscription %d not found: %v", delivery.SubscriptionID, err), true)
		return
	}
	if !sub.Active {
		d.fail(ctx, delivery, 0, "subscription is inactive", true)
		return
	}

	secret, err := d.secret(sub)
	if err != nil {
		// Undecryptable secret means a changed or missing SECRET_KEY_BASE —
		// an operator problem, not the target's. Retry rather than dead-letter,
		// so fixing the key recovers the queue.
		d.fail(ctx, delivery, 0, "cannot decrypt the signing secret", false)
		return
	}

	body, err := json.Marshal(map[string]any(delivery.Payload))
	if err != nil {
		d.fail(ctx, delivery, 0, fmt.Sprintf("payload is not serializable: %v", err), true)
		return
	}

	status, err := d.send(ctx, sub.URL, secret, delivery, body)
	switch {
	case err != nil:
		d.fail(ctx, delivery, status, err.Error(), false)
	case status >= 200 && status < 300:
		if mErr := d.repo.MarkDelivered(ctx, delivery.ID, status); mErr != nil {
			logger.WithFields(logger.Fields{"error": mErr.Error(), "delivery": delivery.ID}).
				Error("A3: could not record a successful webhook delivery")
		}
	case status == http.StatusGone:
		// 410 Gone is the subscriber saying "stop sending". Honour it instead
		// of hammering the endpoint to the attempt limit.
		d.fail(ctx, delivery, status, "target returned 410 Gone", true)
	default:
		d.fail(ctx, delivery, status, fmt.Sprintf("target returned HTTP %d", status), false)
	}
}

// send posts the signed payload. It returns the status code (0 when no response
// was obtained) and an error for transport-level failures.
func (d *WebhookDispatcher) send(ctx context.Context, url, secret string, delivery *model.WebhookDelivery, body []byte) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("building the request: %w", err)
	}

	ts := time.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Socrate-Webhooks/1")
	req.Header.Set(SignatureHeader, SignPayload(secret, ts, body))
	req.Header.Set(EventHeader, string(delivery.EventType))
	req.Header.Set(DeliveryHeader, strconv.FormatUint(uint64(delivery.ID), 10))
	req.Header.Set(AttemptHeader, strconv.Itoa(delivery.Attempts+1))

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain a bounded prefix so the connection closes cleanly; the content is
	// deliberately discarded — a subscriber's response body is not data we act on.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))

	return resp.StatusCode, nil
}

// fail records a failed attempt, dead-lettering when the attempts are spent or
// the caller says the failure is terminal.
func (d *WebhookDispatcher) fail(ctx context.Context, delivery *model.WebhookDelivery, status int, reason string, terminal bool) {
	attempts := delivery.Attempts + 1
	dead := terminal || attempts >= d.maxAttempts
	next := time.Now().Add(BackoffFor(attempts))

	if err := d.repo.MarkFailed(ctx, delivery.ID, status, reason, next, dead); err != nil {
		logger.WithFields(logger.Fields{"error": err.Error(), "delivery": delivery.ID}).
			Error("A3: could not record a failed webhook delivery")
		return
	}

	fields := logger.Fields{
		"delivery":   delivery.ID,
		"event":      string(delivery.EventType),
		"attempt":    attempts,
		"status":     status,
		"reason":     reason,
		"dead":       dead,
		"next_retry": next.UTC().Format(time.RFC3339),
	}
	if dead {
		logger.WithFields(fields).Error("A3: webhook delivery dead-lettered")
	} else {
		logger.WithFields(fields).Warn("A3: webhook delivery failed; will retry")
	}
}

// BackoffFor returns the delay before attempt n+1, given n attempts so far:
// 30s, 1m, 2m, 4m, 8m, … capped at backoffCap. Exponential so a target that is
// down briefly is retried quickly, while one that is down for hours is not
// hammered.
func BackoffFor(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	// Cap the exponent before shifting so the arithmetic cannot overflow.
	if attempts > 20 {
		return backoffCap
	}
	d := 30 * time.Second * time.Duration(math.Pow(2, float64(attempts-1)))
	if d > backoffCap || d <= 0 {
		return backoffCap
	}
	return d
}

// SignPayload builds the X-Socrate-Signature value: `t=<unix>,v1=<hex>` where
// the MAC is HMAC-SHA256 over `<t>.<body>`. Exported so the docs, the tests and
// any first-party verifier agree on one implementation.
func SignPayload(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return fmt.Sprintf("t=%d,%s=%s", ts, SignatureVersion, hex.EncodeToString(mac.Sum(nil)))
}

// VerifySignature checks a signature header against the body, rejecting one
// whose timestamp is outside tolerance. It is the reference implementation a
// subscriber should mirror; Socrate itself uses it only in tests.
func VerifySignature(secret, header string, body []byte, now time.Time, tolerance time.Duration) bool {
	var tsStr, sig string
	for _, part := range bytes.Split([]byte(header), []byte(",")) {
		kv := bytes.SplitN(bytes.TrimSpace(part), []byte("="), 2)
		if len(kv) != 2 {
			continue
		}
		switch string(kv[0]) {
		case "t":
			tsStr = string(kv[1])
		case SignatureVersion:
			sig = string(kv[1])
		}
	}
	if tsStr == "" || sig == "" {
		return false
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	// Reject a stale (or future-dated) timestamp: without this the signature
	// is replayable forever.
	age := now.Sub(time.Unix(ts, 0))
	if age > tolerance || age < -tolerance {
		return false
	}

	expected := SignPayload(secret, ts, body)
	// Constant-time comparison over the whole header value.
	return hmac.Equal([]byte(expected), []byte(header))
}
