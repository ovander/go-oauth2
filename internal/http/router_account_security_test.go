package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/service"
	internalweb "github.com/ovander/go-oauth2/internal/web"
)

// Neither service is called by these requests (a GET, and posts refused for
// their missing CSRF cookie); the embedded nil interfaces fail loudly if one is.
type accountRouteAuth struct{ service.AuthService }
type accountRouteMFA struct{ service.MFAService }

func accountRouter(t *testing.T, on bool) nethttp.Handler {
	t.Helper()
	login := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit: 1, Window: time.Minute, MaxEntries: 100, CleanupInterval: time.Hour,
	})
	t.Cleanup(login.Stop)
	cfg := RouterConfig{LoginRateLimiter: login, SignupRateLimiter: login, TokenRateLimiter: login}
	if on {
		h, err := internalweb.NewAccountSecurityHandler(accountRouteAuth{}, accountRouteMFA{},
			[]byte("router-test-secret-at-least-32-bytes!!"), "https://auth.example")
		if err != nil {
			t.Fatal(err)
		}
		cfg.AccountSecurityHandler = h
	}
	return newOAuthRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, cfg)
}

func accountRequest(h nethttp.Handler, method string) int {
	req := httptest.NewRequest(method, "/account/security", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// ACCOUNT_SECURITY_PAGE=off (the default) leaves the route unregistered.
func TestAccountSecurityPage_OffByDefault(t *testing.T) {
	h := accountRouter(t, false)
	for _, m := range []string{nethttp.MethodGet, nethttp.MethodPost} {
		if code := accountRequest(h, m); code != nethttp.StatusNotFound && code != nethttp.StatusMethodNotAllowed {
			t.Errorf("%s with the page off = %d, want 404/405", m, code)
		}
	}
}

// With it on, every post checks a password or a code, so they share the login
// rate limit.
func TestAccountSecurityPage_PostsShareTheLoginLimit(t *testing.T) {
	h := accountRouter(t, true)
	if code := accountRequest(h, nethttp.MethodGet); code != nethttp.StatusOK {
		t.Fatalf("GET = %d, want 200", code)
	}
	accountRequest(h, nethttp.MethodPost) // spends the 1/min budget
	if code := accountRequest(h, nethttp.MethodPost); code != nethttp.StatusTooManyRequests {
		t.Errorf("second POST = %d, want 429", code)
	}
}
