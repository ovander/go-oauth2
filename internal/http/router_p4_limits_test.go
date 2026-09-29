package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/middleware"
)

// P4-3 / P4-4 route-level checks against the real OAuth router. Handlers are
// nil: the assertions only concern middleware that runs BEFORE any handler
// (the body cap trips inside json.Decode before a field is touched; the
// limiter answers 429 without reaching the handler).

func p4Router(t *testing.T) nethttp.Handler {
	t.Helper()
	tight := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit: 1, Window: time.Minute, MaxEntries: 100, CleanupInterval: time.Hour,
	})
	loose := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit: 1000, Window: time.Minute, MaxEntries: 100, CleanupInterval: time.Hour,
	})
	t.Cleanup(tight.Stop)
	t.Cleanup(loose.Stop)
	return newOAuthRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, RouterConfig{
		TokenRateLimiter: tight, LoginRateLimiter: loose, SignupRateLimiter: loose,
	})
}

func p4Post(h nethttp.Handler, path, body string) int {
	req := httptest.NewRequest(nethttp.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:4444"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestP44_IntrospectAndRevoke_ShareTheTokenEndpointBudget(t *testing.T) {
	for _, path := range []string{"/oauth/introspect", "/oauth/revoke"} {
		h := p4Router(t)
		p4Post(h, path, "token=x") // first request spends the 1/min budget (handler is nil → 500, irrelevant)
		if code := p4Post(h, path, "token=x"); code != nethttp.StatusTooManyRequests {
			t.Errorf("%s: second request = %d, want 429", path, code)
		}
	}
}

func TestP43_OversizeJSONBodyIsRejectedBeforeDecoding(t *testing.T) {
	h := p4Router(t)
	huge := `{"email":"` + strings.Repeat("a", int(middleware.DefaultMaxRequestBody)+1024) + `","password":"x","app_client_id":"c"}`
	if code := p4Post(h, "/api/auth/login", huge); code != nethttp.StatusBadRequest {
		t.Fatalf("oversize login body = %d, want 400", code)
	}
}
