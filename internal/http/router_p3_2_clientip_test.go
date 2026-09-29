// Package http — regression tests for P3-2 (GO-2026-5775 / GO-2026-5777).
//
// chi's middleware.RealIP was installed unconditionally on every router and
// rewrote r.RemoteAddr from True-Client-IP / X-Real-IP / X-Forwarded-For for
// ANY peer, so the per-IP rate limiter, IP blocking, auto-defense attribution
// and audit logging all trusted an attacker-chosen address. RealIP is gone;
// middleware.ClientIP resolves the IP once, honouring proxy headers only from
// TRUSTED_PROXIES.
//
// These tests exercise the real OAuth router end-to-end: a peer that is not a
// trusted proxy must not be able to escape the login rate limiter by rotating
// the headers RealIP used to trust.
package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/middleware"
)

func newP32Limiter() *middleware.RateLimiter {
	return middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit:           1,
		Window:          time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Hour,
	})
}

// TestP32_SpoofedIPHeaders_DoNotBypassRateLimiter proves the property that
// RealIP broke: with no trusted proxies, rotating True-Client-IP / X-Real-IP /
// X-Forwarded-For across requests from the same peer must not reset the
// per-IP counter.
func TestP32_SpoofedIPHeaders_DoNotBypassRateLimiter(t *testing.T) {
	limiter := newP32Limiter()
	defer limiter.Stop()

	handler := middleware.ClientIP(nil)(
		middleware.RateLimitMiddleware(limiter, nil)(nopRefreshHandler),
	)

	send := func(hdr, val string) int {
		req := httptest.NewRequest(nethttp.MethodPost, "/api/auth/refresh", nil)
		req.RemoteAddr = "203.0.113.9:4242"
		if hdr != "" {
			req.Header.Set(hdr, val)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := send("", ""); code != nethttp.StatusOK {
		t.Fatalf("first request: got %d, want 200", code)
	}
	spoofs := [][2]string{
		{"True-Client-IP", "198.51.100.1"},
		{"X-Real-IP", "198.51.100.2"},
		{"X-Forwarded-For", "198.51.100.3"},
		{"X-Forwarded-For", "198.51.100.4, 10.0.0.1"},
	}
	for _, s := range spoofs {
		if code := send(s[0], s[1]); code != nethttp.StatusTooManyRequests {
			t.Errorf("P3-2: %s=%q escaped the rate limiter (got %d, want 429)", s[0], s[1], code)
		}
	}
}

// TestP32_TrustedProxy_ForwardedFor_StillKeysPerClient proves the legitimate
// case survives: behind a trusted loopback proxy (Caddy), distinct clients in
// X-Forwarded-For get independent counters.
func TestP32_TrustedProxy_ForwardedFor_StillKeysPerClient(t *testing.T) {
	limiter := newP32Limiter()
	defer limiter.Stop()

	trusted, err := middleware.ParseTrustedProxyCIDRs("127.0.0.1/32,::1/128")
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware.ClientIP(trusted)(
		middleware.RateLimitMiddleware(limiter, trusted)(nopRefreshHandler),
	)

	send := func(xff string) int {
		req := httptest.NewRequest(nethttp.MethodPost, "/api/auth/refresh", nil)
		req.RemoteAddr = "127.0.0.1:55555"
		req.Header.Set("X-Forwarded-For", xff)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := send("198.51.100.7"); code != nethttp.StatusOK {
		t.Fatalf("client A first request: got %d, want 200", code)
	}
	if code := send("198.51.100.7"); code != nethttp.StatusTooManyRequests {
		t.Fatalf("client A second request: got %d, want 429", code)
	}
	if code := send("198.51.100.8"); code != nethttp.StatusOK {
		t.Fatalf("client B must have its own counter: got %d, want 200", code)
	}
}
