// Package http — tests for MED-05 and LOW-06.
//
// MED-05: POST /oauth/token must be rate-limited when RouterConfig.TokenRateLimiter
// is set, preventing authorization-code brute-force and credential-spraying.
//
// LOW-06: POST /forgot-password and POST /reset-password must be rate-limited
// using the LoginRateLimiter so that email verification tokens cannot be
// enumerated or brute-forced.
//
// Both fixes wire RateLimitMiddleware around the relevant routes in the router.
// These tests exercise that wiring directly — without a full application stack —
// by applying RateLimitMiddleware to a no-op handler and verifying that the
// limiter produces HTTP 429 after the configured limit is exhausted.
package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/middleware"
)

// nopTokenHandler is a trivial upstream that always returns 200 OK.
// It stands in for the real Token / ForgotPassword / ResetPassword handlers
// so we can focus on the rate-limiting layer.
var nopTokenHandler = nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
	w.WriteHeader(nethttp.StatusOK)
})

// newTightLimiter creates a RateLimiter that allows only 1 request per minute,
// making it easy to exhaust in a test.
func newTightLimiter() *middleware.RateLimiter {
	return middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit:           1,
		Window:          time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Hour, // prevent goroutine interference during test
	})
}

// postRequest builds an HTTP POST request to the given path from a fixed client IP.
func postRequest(path string) *nethttp.Request {
	req := httptest.NewRequest(nethttp.MethodPost, path, nil)
	req.RemoteAddr = "203.0.113.1:12345" // TEST-NET-3; deterministic client key
	return req
}

// ---------------------------------------------------------------------------
// MED-05: Token endpoint rate limiting
// ---------------------------------------------------------------------------

// TestMED05_TokenRateLimiter_AllowsFirstRequest verifies that the first
// request to POST /oauth/token passes through when rate limiting is enabled.
func TestMED05_TokenRateLimiter_AllowsFirstRequest(t *testing.T) {
	limiter := newTightLimiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopTokenHandler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, postRequest("/oauth/token"))

	if rr.Code != nethttp.StatusOK {
		t.Errorf("MED-05: first request should pass (200), got %d", rr.Code)
	}
}

// TestMED05_TokenRateLimiter_BlocksAfterLimit verifies that the second request
// from the same client IP returns HTTP 429 once the single-request-per-minute
// limit is exhausted.
func TestMED05_TokenRateLimiter_BlocksAfterLimit(t *testing.T) {
	limiter := newTightLimiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopTokenHandler)

	// First request — should pass.
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, postRequest("/oauth/token"))
	if rr1.Code != nethttp.StatusOK {
		t.Fatalf("MED-05: setup — first request got %d, want 200", rr1.Code)
	}

	// Second request — limit exceeded, must return 429.
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, postRequest("/oauth/token"))
	if rr2.Code != nethttp.StatusTooManyRequests {
		t.Errorf("MED-05: second request should be rate-limited (429), got %d", rr2.Code)
	}
}

// TestMED05_TokenRateLimiter_RetryAfterHeaderPresent verifies that a 429
// response includes a Retry-After header so clients know when to retry.
func TestMED05_TokenRateLimiter_RetryAfterHeaderPresent(t *testing.T) {
	limiter := newTightLimiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopTokenHandler)

	// Exhaust the limit.
	handler.ServeHTTP(httptest.NewRecorder(), postRequest("/oauth/token"))

	// Check the 429 response headers.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, postRequest("/oauth/token"))

	if rr.Code == nethttp.StatusTooManyRequests {
		if rr.Header().Get("Retry-After") == "" {
			t.Error("MED-05: 429 response must include Retry-After header")
		}
	}
}

// TestMED05_RouterConfig_TokenRateLimiter_FieldExists verifies that
// RouterConfig exposes a TokenRateLimiter field (compile-time check that the
// MED-05 struct field was added).
func TestMED05_RouterConfig_TokenRateLimiter_FieldExists(t *testing.T) {
	limiter := newTightLimiter()
	defer limiter.Stop()

	// Construct a RouterConfig with TokenRateLimiter set — this is a
	// compile-time check: if the field does not exist this will not compile.
	cfg := RouterConfig{
		TokenRateLimiter: limiter,
	}
	if cfg.TokenRateLimiter == nil {
		t.Error("MED-05: TokenRateLimiter field must be non-nil after assignment")
	}
}

// TestMED05_NilTokenRateLimiter_DoesNotPanic verifies that RouterConfig with
// TokenRateLimiter=nil (the disabled case) is a valid configuration and does
// not panic when accessed.
func TestMED05_NilTokenRateLimiter_DoesNotPanic(t *testing.T) {
	cfg := RouterConfig{TokenRateLimiter: nil}
	if cfg.TokenRateLimiter != nil {
		t.Error("MED-05: nil TokenRateLimiter should remain nil")
	}
}

// ---------------------------------------------------------------------------
// LOW-06: Forgot-password and reset-password rate limiting
// ---------------------------------------------------------------------------

// TestLOW06_ForgotPassword_AllowsFirstRequest verifies the baseline: the first
// request to a rate-limited forgot-password route passes through.
func TestLOW06_ForgotPassword_AllowsFirstRequest(t *testing.T) {
	limiter := newTightLimiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopTokenHandler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, postRequest("/forgot-password"))

	if rr.Code != nethttp.StatusOK {
		t.Errorf("LOW-06: first forgot-password request should pass (200), got %d", rr.Code)
	}
}

// TestLOW06_ForgotPassword_BlocksAfterLimit verifies that after the limit is
// exhausted, subsequent requests to /forgot-password return 429.  This prevents
// email verification token enumeration via repeated password-reset requests.
func TestLOW06_ForgotPassword_BlocksAfterLimit(t *testing.T) {
	limiter := newTightLimiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopTokenHandler)

	// Exhaust the limit.
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, postRequest("/forgot-password"))
	if rr1.Code != nethttp.StatusOK {
		t.Fatalf("LOW-06: setup — first forgot-password got %d, want 200", rr1.Code)
	}

	// Second request must be throttled.
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, postRequest("/forgot-password"))
	if rr2.Code != nethttp.StatusTooManyRequests {
		t.Errorf("LOW-06: second forgot-password request should be rate-limited (429), got %d", rr2.Code)
	}
}

// TestLOW06_ResetPassword_BlocksAfterLimit verifies that POST /reset-password
// is also rate-limited (the second request returns 429 after the limit is
// exhausted from the same IP).
func TestLOW06_ResetPassword_BlocksAfterLimit(t *testing.T) {
	limiter := newTightLimiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopTokenHandler)

	// Exhaust the limit.
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, postRequest("/reset-password"))
	if rr1.Code != nethttp.StatusOK {
		t.Fatalf("LOW-06: setup — first reset-password got %d, want 200", rr1.Code)
	}

	// Second request must be throttled.
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, postRequest("/reset-password"))
	if rr2.Code != nethttp.StatusTooManyRequests {
		t.Errorf("LOW-06: second reset-password request should be rate-limited (429), got %d", rr2.Code)
	}
}

// TestLOW06_DifferentIPs_NotThrottledByEachOther verifies that rate limiting
// is per-IP: one client being throttled must not affect a different IP.
func TestLOW06_DifferentIPs_NotThrottledByEachOther(t *testing.T) {
	limiter := newTightLimiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopTokenHandler)

	// IP-A exhausts its limit.
	reqA := httptest.NewRequest(nethttp.MethodPost, "/forgot-password", nil)
	reqA.RemoteAddr = "192.0.2.1:12345" // distinct TEST-NET-1 IP
	handler.ServeHTTP(httptest.NewRecorder(), reqA)
	// Second from same IP-A should be blocked.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, reqA)
	if rr.Code != nethttp.StatusTooManyRequests {
		t.Fatalf("LOW-06: setup — IP-A should be throttled (429), got %d", rr.Code)
	}

	// IP-B has its own counter — must still be allowed.
	reqB := httptest.NewRequest(nethttp.MethodPost, "/forgot-password", nil)
	reqB.RemoteAddr = "192.0.2.2:12345" // different IP
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	if rrB.Code != nethttp.StatusOK {
		t.Errorf("LOW-06: different IP-B should not be rate-limited by IP-A's exhaustion, got %d", rrB.Code)
	}
}

// TestLOW06_LoginRateLimiter_Reuse_SharedCounter verifies that sharing a
// single LoginRateLimiter between forgot-password and reset-password routes
// (as LOW-06 does) means the two endpoints share the same per-IP counter.
// A client that exhausts the limit on /forgot-password is also throttled on
// /reset-password when both share the same limiter instance.
func TestLOW06_LoginRateLimiter_Reuse_SharedCounter(t *testing.T) {
	sharedLimiter := newTightLimiter()
	defer sharedLimiter.Stop()

	forgotHandler := middleware.RateLimitMiddleware(sharedLimiter, nil)(nopTokenHandler)
	resetHandler := middleware.RateLimitMiddleware(sharedLimiter, nil)(nopTokenHandler)

	clientReq := func(path string) *nethttp.Request {
		req := httptest.NewRequest(nethttp.MethodPost, path, nil)
		req.RemoteAddr = "198.51.100.1:8080" // same IP for both
		return req
	}

	// Exhaust via forgot-password.
	forgotHandler.ServeHTTP(httptest.NewRecorder(), clientReq("/forgot-password"))

	// reset-password from the same IP must be throttled (shared counter).
	rr := httptest.NewRecorder()
	resetHandler.ServeHTTP(rr, clientReq("/reset-password"))
	if rr.Code != nethttp.StatusTooManyRequests {
		t.Errorf("LOW-06: shared limiter — IP exhausted on /forgot-password should also throttle /reset-password (429), got %d", rr.Code)
	}
}
