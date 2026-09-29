package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/internal/shared/ssrf"
)

// dispatcherHarness wires a service, a repo and a live test server together,
// pointing the SSRF resolver at the server's own address so delivery actually
// happens over HTTP without leaving the machine.
type dispatcherHarness struct {
	svc  WebhookService
	repo *memWebhookRepo
	sub  *model.WebhookSubscription
	sec  string
	srv  *httptest.Server
}

// newDispatcherHarness starts a target server with the given handler and
// registers a subscription pointing at it.
func newDispatcherHarness(t *testing.T, handler http.HandlerFunc) *dispatcherHarness {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	host := u.Hostname()
	port := u.Port()

	// Resolve a stable name to the test server so the request URL is a real
	// hostname rather than a literal. The address guard itself is bypassed in
	// newGuardedTestClient (httptest is on loopback) and tested directly in the
	// ssrf package instead.
	origResolver := ssrf.Resolver
	ssrf.Resolver = func(h string) ([]net.IP, error) {
		if h == "target.test" {
			return []net.IP{net.ParseIP(host)}, nil
		}
		return nil, fmt.Errorf("no such host: %s", h)
	}
	t.Cleanup(func() { ssrf.Resolver = origResolver })

	repo := newMemWebhookRepo()
	svc := NewWebhookService(repo, []byte(strings.Repeat("k", 32)))

	// Build the subscription directly: Create would run the SSRF URL check,
	// which refuses the loopback target by design.
	sub := &model.WebhookSubscription{
		Name:       "target",
		URL:        fmt.Sprintf("https://target.test:%s/hook", port),
		EventTypes: model.StringArray{model.WebhookEventWildcard},
		Active:     true,
	}
	secret := "whsec_test_secret"
	enc, err := encryptForTest(secret)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	sub.SecretEnc = enc
	if err := repo.CreateSubscription(context.Background(), sub); err != nil {
		t.Fatalf("create subscription: %v", err)
	}

	return &dispatcherHarness{svc: svc, repo: repo, sub: sub, sec: secret, srv: srv}
}

// encryptForTest mirrors what the service does when storing a secret.
func encryptForTest(secret string) (string, error) {
	return auth.EncryptSecret([]byte(strings.Repeat("k", 32)), secret)
}

// newGuardedTestClient returns the dispatcher's real client with two
// concessions to the test environment: certificate verification is relaxed
// (httptest serves a self-signed cert) and the address guard is bypassed
// (httptest listens on loopback, which the guard rightly refuses).
//
// The no-redirect policy — which lives on the Client, not the Transport — is
// untouched, so TestDispatcher_DoesNotFollowRedirects still exercises the real
// thing. The address guard it bypasses is covered directly in the ssrf package
// (TestGuardedDial_*), which is where that behaviour belongs.
func newGuardedTestClient(serverAddr string) *http.Client {
	c := ssrf.NewHTTPClient(5 * time.Second)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		panic("ssrf.NewHTTPClient no longer uses *http.Transport; update this helper")
	}
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // G402: test-only, against httptest's self-signed cert
	plain := &net.Dialer{Timeout: 5 * time.Second}
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return plain.DialContext(ctx, network, serverAddr)
	}
	return c
}

// enqueue seeds one pending delivery due now.
func (h *dispatcherHarness) enqueue(t *testing.T, payload model.JSONMap) uint {
	t.Helper()
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()
	h.repo.nextDelID++
	id := h.repo.nextDelID
	h.repo.deliveries[id] = model.WebhookDelivery{
		ID:             id,
		SubscriptionID: h.sub.ID,
		EventType:      model.WebhookLoginFailed,
		Payload:        payload,
		Status:         model.WebhookDeliveryPending,
		NextAttemptAt:  time.Now().Add(-time.Second),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	return id
}

func (h *dispatcherHarness) get(t *testing.T, id uint) model.WebhookDelivery {
	t.Helper()
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()
	return h.repo.deliveries[id]
}

func (h *dispatcherHarness) dispatcher(cfg DispatcherConfig) *WebhookDispatcher {
	d := NewWebhookDispatcher(h.repo, h.svc, cfg)
	d.client = newGuardedTestClient(h.srv.Listener.Addr().String())
	return d
}

// A 2xx marks the delivery delivered, and the request carries a verifiable
// signature over the exact body.
func TestDispatcher_DeliversAndSigns(t *testing.T) {
	var (
		mu     sync.Mutex
		gotSig string
		gotEv  string
		gotAtt string
		gotBod []byte
	)
	h := newDispatcherHarness(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotSig = r.Header.Get(SignatureHeader)
		gotEv = r.Header.Get(EventHeader)
		gotAtt = r.Header.Get(AttemptHeader)
		gotBod = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	id := h.enqueue(t, model.JSONMap{"event": "login.failed", "event_id": 99})

	n, err := h.dispatcher(DispatcherConfig{}).DispatchOnce(context.Background())
	if err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("attempted %d deliveries, want 1", n)
	}

	d := h.get(t, id)
	if d.Status != model.WebhookDeliveryDelivered {
		t.Fatalf("status = %q (%s), want delivered", d.Status, d.LastError)
	}
	if d.Attempts != 1 || d.DeliveredAt == nil || d.LastStatusCode != 200 {
		t.Errorf("delivered row = %+v", d)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotEv != string(model.WebhookLoginFailed) {
		t.Errorf("%s = %q", EventHeader, gotEv)
	}
	if gotAtt != "1" {
		t.Errorf("%s = %q, want 1", AttemptHeader, gotAtt)
	}
	if !VerifySignature(h.sec, gotSig, gotBod, time.Now(), time.Minute) {
		t.Errorf("signature %q does not verify over the received body", gotSig)
	}
	// A different secret must not verify.
	if VerifySignature("whsec_wrong", gotSig, gotBod, time.Now(), time.Minute) {
		t.Error("signature verified under the wrong secret")
	}
	// Nor a tampered body.
	if VerifySignature(h.sec, gotSig, append(gotBod, ' '), time.Now(), time.Minute) {
		t.Error("signature verified over a tampered body")
	}
}

// A 5xx is retried with backoff, not dead-lettered, until the attempts run out.
func TestDispatcher_RetriesThenDeadLetters(t *testing.T) {
	var hits int
	var mu sync.Mutex
	h := newDispatcherHarness(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	})

	id := h.enqueue(t, model.JSONMap{"event": "login.failed"})
	d := h.dispatcher(DispatcherConfig{MaxAttempts: 3})

	// Attempt 1 → still pending, scheduled out.
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	row := h.get(t, id)
	if row.Status != model.WebhookDeliveryPending || row.Attempts != 1 {
		t.Fatalf("after attempt 1: %+v", row)
	}
	if !row.NextAttemptAt.After(time.Now()) {
		t.Error("next attempt was not pushed into the future")
	}
	if row.LastStatusCode != 500 || !strings.Contains(row.LastError, "500") {
		t.Errorf("failure not recorded: %+v", row)
	}

	// Make it due again and burn the remaining attempts.
	for i := 2; i <= 3; i++ {
		h.repo.mu.Lock()
		r := h.repo.deliveries[id]
		r.NextAttemptAt = time.Now().Add(-time.Second)
		h.repo.deliveries[id] = r
		h.repo.mu.Unlock()

		if _, err := d.DispatchOnce(context.Background()); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}

	row = h.get(t, id)
	if row.Status != model.WebhookDeliveryDead {
		t.Fatalf("after %d attempts status = %q, want dead", row.Attempts, row.Status)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 3 {
		t.Errorf("target was hit %d times, want 3", hits)
	}
}

// 410 Gone is the subscriber asking to stop; it is terminal immediately rather
// than being retried to the attempt limit.
func TestDispatcher_GoneIsTerminal(t *testing.T) {
	h := newDispatcherHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	})
	id := h.enqueue(t, model.JSONMap{"event": "login.failed"})

	if _, err := h.dispatcher(DispatcherConfig{MaxAttempts: 10}).DispatchOnce(context.Background()); err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}
	row := h.get(t, id)
	if row.Status != model.WebhookDeliveryDead || row.Attempts != 1 {
		t.Fatalf("410 should dead-letter on the first attempt: %+v", row)
	}
}

// A redirect is refused rather than followed — following one would undo the
// SSRF check, since a public URL can redirect to a private address.
func TestDispatcher_DoesNotFollowRedirects(t *testing.T) {
	h := newDispatcherHarness(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:8081/api/admin/apps", http.StatusFound)
	})
	id := h.enqueue(t, model.JSONMap{"event": "login.failed"})

	if _, err := h.dispatcher(DispatcherConfig{MaxAttempts: 3}).DispatchOnce(context.Background()); err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}
	row := h.get(t, id)
	if row.Status == model.WebhookDeliveryDelivered {
		t.Fatal("a redirect was followed and counted as delivered")
	}
	if !strings.Contains(strings.ToLower(row.LastError), "redirect") {
		t.Errorf("expected a redirect error, got %q", row.LastError)
	}
}

// An inactive subscription's deliveries are dead-lettered rather than sent.
func TestDispatcher_InactiveSubscriptionIsTerminal(t *testing.T) {
	var hits int
	h := newDispatcherHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})

	h.repo.mu.Lock()
	s := h.repo.subs[h.sub.ID]
	s.Active = false
	h.repo.subs[h.sub.ID] = s
	h.repo.mu.Unlock()

	id := h.enqueue(t, model.JSONMap{"event": "login.failed"})
	if _, err := h.dispatcher(DispatcherConfig{}).DispatchOnce(context.Background()); err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}
	row := h.get(t, id)
	if row.Status != model.WebhookDeliveryDead {
		t.Fatalf("status = %q, want dead", row.Status)
	}
	if hits != 0 {
		t.Errorf("target was contacted %d times for an inactive subscription", hits)
	}
}

// Claiming leases a row so a concurrent pass cannot take the same one — this is
// what stops two instances double-sending.
func TestDispatcher_ClaimLeasesTheRow(t *testing.T) {
	h := newDispatcherHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h.enqueue(t, model.JSONMap{"event": "login.failed"})

	first, err := h.repo.ClaimDue(context.Background(), 10, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("first claim took %d rows, want 1", len(first))
	}

	second, err := h.repo.ClaimDue(context.Background(), 10, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("second claim took %d rows; the lease did not hold", len(second))
	}
}

// The payload sent is exactly the frozen payload, so a retry is byte-identical
// and the signature stays reproducible.
func TestDispatcher_SendsTheFrozenPayload(t *testing.T) {
	var got []byte
	var mu sync.Mutex
	h := newDispatcherHarness(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = b
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	payload := model.JSONMap{"event": "login.failed", "event_id": float64(7), "ip_address": "203.0.113.9"}
	h.enqueue(t, payload)

	if _, err := h.dispatcher(DispatcherConfig{}).DispatchOnce(context.Background()); err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	var back map[string]any
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	for k, want := range payload {
		if back[k] != want {
			t.Errorf("payload[%q] = %#v, want %#v", k, back[k], want)
		}
	}
}

func TestBackoffFor(t *testing.T) {
	cases := map[int]time.Duration{
		0: 30 * time.Second, // clamped to attempt 1
		1: 30 * time.Second,
		2: time.Minute,
		3: 2 * time.Minute,
		4: 4 * time.Minute,
		5: 8 * time.Minute,
	}
	for attempts, want := range cases {
		if got := BackoffFor(attempts); got != want {
			t.Errorf("BackoffFor(%d) = %v, want %v", attempts, got, want)
		}
	}
	// Capped, and never negative from overflow.
	for _, n := range []int{6, 10, 40, 1 << 20} {
		got := BackoffFor(n)
		if got <= 0 || got > 15*time.Minute {
			t.Errorf("BackoffFor(%d) = %v, want a positive value capped at 15m", n, got)
		}
	}
}

// The timestamp is inside the signed material, so an old capture does not
// verify — that is what stops replay.
func TestVerifySignature_RejectsStaleAndMalformed(t *testing.T) {
	secret := "whsec_x"
	body := []byte(`{"event":"login.failed"}`)
	now := time.Now()

	fresh := SignPayload(secret, now.Unix(), body)
	if !VerifySignature(secret, fresh, body, now, time.Minute) {
		t.Fatal("a fresh signature did not verify")
	}

	old := SignPayload(secret, now.Add(-10*time.Minute).Unix(), body)
	if VerifySignature(secret, old, body, now, time.Minute) {
		t.Error("a stale signature verified; replay is possible")
	}

	future := SignPayload(secret, now.Add(10*time.Minute).Unix(), body)
	if VerifySignature(secret, future, body, now, time.Minute) {
		t.Error("a future-dated signature verified")
	}

	for _, bad := range []string{"", "garbage", "t=abc,v1=deadbeef", "v1=deadbeef", "t=123"} {
		if VerifySignature(secret, bad, body, now, time.Minute) {
			t.Errorf("malformed header %q verified", bad)
		}
	}
}

// The signature is deterministic for a given (secret, timestamp, body).
func TestSignPayload_Deterministic(t *testing.T) {
	body := []byte(`{"a":1}`)
	a := SignPayload("s", 1700000000, body)
	b := SignPayload("s", 1700000000, body)
	if a != b {
		t.Fatalf("signature is not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "t=1700000000,v1=") {
		t.Fatalf("unexpected format: %q", a)
	}
	if c := SignPayload("s", 1700000001, body); c == a {
		t.Error("signature did not change with the timestamp")
	}
}
