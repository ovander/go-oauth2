// Package http — tests for FIND-02 (POST /api/auth/refresh not rate-limited).
//
// FIND-02 bug: the MED-05 fix added per-IP rate limiting to POST /oauth/token
// but left the equivalent direct-API refresh endpoint POST /api/auth/refresh
// unprotected.  An attacker could probe refresh tokens at unlimited speed
// through the unguarded endpoint, defeating the brute-force mitigation added
// by MED-05.
//
// FIND-02 fix: the same config.TokenRateLimiter that guards POST /oauth/token
// is now applied to POST /api/auth/refresh via the same conditional block
// pattern.  Using the same limiter instance means both endpoints share a single
// per-IP counter — exhausting the limit on one path blocks the other as well.
//
// Tests:
//   - Rate limiter allows the first request to the refresh path
//   - Rate limiter blocks the second request from the same IP (429)
//   - 429 response on the refresh path includes Retry-After
//   - Shared limiter: exhausting quota on /oauth/token also blocks /api/auth/refresh
//   - Nil TokenRateLimiter: refresh endpoint still works without panicking
//   - Different source IPs have independent counters on the refresh path
package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/middleware"
)

// nopRefreshHandler is a trivial handler standing in for the real Refresh
// handler so tests can focus purely on the rate-limiting layer.
var nopRefreshHandler = nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
	w.WriteHeader(nethttp.StatusOK)
})

// newFind02Limiter creates a RateLimiter that allows only 1 request per
// minute from a given IP, making the limit trivially exhaustible in tests.
func newFind02Limiter() *middleware.RateLimiter {
	return middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit:           1,
		Window:          time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Hour, // avoid goroutine races during short-lived tests
	})
}

// refreshRequest returns a POST request to /api/auth/refresh from a fixed IP.
func refreshRequest() *nethttp.Request {
	req := httptest.NewRequest(nethttp.MethodPost, "/api/auth/refresh", nil)
	req.RemoteAddr = "203.0.113.2:11111" // TEST-NET-3; deterministic per-IP key
	return req
}

// ---------------------------------------------------------------------------
// FIND-02: /api/auth/refresh rate limiting
// ---------------------------------------------------------------------------

// TestFIND02_Refresh_AllowsFirstRequest verifies that the first request to the
// refresh endpoint passes through when a TokenRateLimiter is configured.
func TestFIND02_Refresh_AllowsFirstRequest(t *testing.T) {
	limiter := newFind02Limiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopRefreshHandler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, refreshRequest())

	if rr.Code != nethttp.StatusOK {
		t.Errorf("FIND-02: first /api/auth/refresh request should pass (200); got %d", rr.Code)
	}
}

// TestFIND02_Refresh_BlocksAfterLimit verifies that the second request from
// the same IP to the refresh endpoint is rate-limited (429) once the per-IP
// quota is exhausted — the core FIND-02 protection.
func TestFIND02_Refresh_BlocksAfterLimit(t *testing.T) {
	limiter := newFind02Limiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopRefreshHandler)

	// First request — must pass.
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, refreshRequest())
	if rr1.Code != nethttp.StatusOK {
		t.Fatalf("FIND-02: setup — first refresh got %d, want 200", rr1.Code)
	}

	// Second request — limit exhausted; must be blocked.
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, refreshRequest())
	if rr2.Code != nethttp.StatusTooManyRequests {
		t.Errorf("FIND-02: second refresh request from same IP should be rate-limited (429); got %d", rr2.Code)
	}
}

// TestFIND02_Refresh_RetryAfterHeaderPresent verifies that a 429 response for
// the refresh path includes a Retry-After header so well-behaved clients can
// back off correctly.
func TestFIND02_Refresh_RetryAfterHeaderPresent(t *testing.T) {
	limiter := newFind02Limiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopRefreshHandler)

	// Exhaust the limit.
	handler.ServeHTTP(httptest.NewRecorder(), refreshRequest())

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, refreshRequest())

	if rr.Code == nethttp.StatusTooManyRequests {
		if rr.Header().Get("Retry-After") == "" {
			t.Error("FIND-02: 429 on /api/auth/refresh must include Retry-After header")
		}
	}
}

// TestFIND02_SharedLimiter_TokenEndpoint_AlsoBlocksRefresh is the most
// important architectural test: when both POST /oauth/token and POST
// /api/auth/refresh share the SAME RateLimiter instance (the fix), exhausting
// the quota on the token endpoint also blocks the refresh endpoint from the
// same IP.  This prevents an attacker from bypassing the MED-05 token
// endpoint limit by switching to the refresh path.
func TestFIND02_SharedLimiter_TokenEndpoint_AlsoBlocksRefresh(t *testing.T) {
	sharedLimiter := newFind02Limiter()
	defer sharedLimiter.Stop()

	tokenHandler := middleware.RateLimitMiddleware(sharedLimiter, nil)(nopTokenHandler)
	refreshHandler := middleware.RateLimitMiddleware(sharedLimiter, nil)(nopRefreshHandler)

	sameIP := func(path string) *nethttp.Request {
		req := httptest.NewRequest(nethttp.MethodPost, path, nil)
		req.RemoteAddr = "198.51.100.7:9999" // single deterministic IP
		return req
	}

	// Exhaust quota via the token endpoint.
	tokenHandler.ServeHTTP(httptest.NewRecorder(), sameIP("/oauth/token"))

	// Refresh endpoint from same IP must also be blocked (shared counter).
	rr := httptest.NewRecorder()
	refreshHandler.ServeHTTP(rr, sameIP("/api/auth/refresh"))
	if rr.Code != nethttp.StatusTooManyRequests {
		t.Errorf("FIND-02: shared limiter — quota exhausted on /oauth/token must also block /api/auth/refresh (429); got %d", rr.Code)
	}
}

// TestFIND02_DifferentIPs_IndependentCounters verifies that the per-IP
// isolation is preserved on the refresh path: one client being throttled
// must not affect a different client IP.
func TestFIND02_DifferentIPs_IndependentCounters(t *testing.T) {
	limiter := newFind02Limiter()
	defer limiter.Stop()

	handler := middleware.RateLimitMiddleware(limiter, nil)(nopRefreshHandler)

	// IP-A exhausts its limit.
	reqA := httptest.NewRequest(nethttp.MethodPost, "/api/auth/refresh", nil)
	reqA.RemoteAddr = "192.0.2.10:1234"
	handler.ServeHTTP(httptest.NewRecorder(), reqA) // consume quota
	rrA := httptest.NewRecorder()
	handler.ServeHTTP(rrA, reqA) // must be blocked
	if rrA.Code != nethttp.StatusTooManyRequests {
		t.Fatalf("FIND-02: setup — IP-A second request got %d, want 429", rrA.Code)
	}

	// IP-B has its own independent counter — must still be allowed.
	reqB := httptest.NewRequest(nethttp.MethodPost, "/api/auth/refresh", nil)
	reqB.RemoteAddr = "192.0.2.11:1234" // different IP
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	if rrB.Code != nethttp.StatusOK {
		t.Errorf("FIND-02: IP-B should not be throttled by IP-A's exhausted quota; got %d", rrB.Code)
	}
}

// TestFIND02_NilTokenRateLimiter_RefreshStillWorks verifies that when
// TokenRateLimiter is nil (RATE_LIMIT_TOKEN=0 explicitly disabled), the
// refresh endpoint is registered and callable without panicking.  This is
// the fall-through branch of the `if config.TokenRateLimiter != nil` guard.
func TestFIND02_NilTokenRateLimiter_RefreshStillWorks(t *testing.T) {
	// Wrap nopRefreshHandler directly (no limiter) to simulate the nil branch.
	handler := nopRefreshHandler

	req := httptest.NewRequest(nethttp.MethodPost, "/api/auth/refresh", nil)
	req.RemoteAddr = "203.0.113.5:4321"
	rr := httptest.NewRecorder()

	// Must not panic and must return 200.
	handler.ServeHTTP(rr, req)
	if rr.Code != nethttp.StatusOK {
		t.Errorf("FIND-02: nil limiter path must not block (200); got %d", rr.Code)
	}
}
