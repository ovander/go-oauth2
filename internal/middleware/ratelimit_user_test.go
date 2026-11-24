package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/contextkeys"
)

// UserRateLimitMiddleware gives each authenticated user their own budget, so
// admins reaching the API through the same BFF address do not share one; a
// request without a user falls back to its client IP; a nil limiter applies no
// limit.
func TestUserRateLimitMiddleware(t *testing.T) {
	limiter := NewRateLimiterWithConfig(RateLimiterConfig{Limit: 1, Window: time.Minute, MaxEntries: 100, CleanupInterval: time.Hour})
	t.Cleanup(limiter.Stop)
	h := UserRateLimitMiddleware(limiter, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	send := func(uid uint, ip string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/admin/elevate", nil)
		r.RemoteAddr = ip + ":1234"
		if uid != 0 {
			r = r.WithContext(context.WithValue(r.Context(), contextkeys.UserIDKey, uid))
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr.Code
	}

	if got := send(1, "127.0.0.1"); got != http.StatusOK {
		t.Fatalf("user 1, first: %d", got)
	}
	if got := send(1, "127.0.0.1"); got != http.StatusTooManyRequests {
		t.Fatalf("user 1, second: %d, want 429", got)
	}
	if got := send(2, "127.0.0.1"); got != http.StatusOK {
		t.Fatalf("user 2 from the same address: %d, want its own budget", got)
	}
	if got := send(0, "203.0.113.5"); got != http.StatusOK {
		t.Fatalf("no user, first: %d", got)
	}
	if got := send(0, "203.0.113.5"); got != http.StatusTooManyRequests {
		t.Fatalf("no user, same IP: %d, want 429", got)
	}

	open := UserRateLimitMiddleware(nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		open.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("nil limiter: %d", rr.Code)
		}
	}
}
