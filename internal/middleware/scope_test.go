package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

func withClaims(scope string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/events", nil)
	claims := &auth.AccessTokenClaims{Scope: scope}
	return req.WithContext(context.WithValue(req.Context(), contextkeys.JWTClaimsKey, claims))
}

func run(t *testing.T, enforce bool, scope, required string) int {
	t.Helper()
	h := RequireScope(required, enforce)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withClaims(scope))
	return rec.Code
}

func TestRequireScope_PassThroughWhenDisabled(t *testing.T) {
	if got := run(t, false, "", "monitoring:read"); got != http.StatusOK {
		t.Fatalf("disabled gate must pass through: got %d", got)
	}
}

func TestRequireScope_AllowsMatchingScope(t *testing.T) {
	if got := run(t, true, "openid monitoring:read monitoring:write", "monitoring:read"); got != http.StatusOK {
		t.Fatalf("matching scope: got %d, want 200", got)
	}
}

func TestRequireScope_AdminIsSuperScope(t *testing.T) {
	if got := run(t, true, "admin", "monitoring:write"); got != http.StatusOK {
		t.Fatalf("admin super-scope: got %d, want 200", got)
	}
}

func TestRequireScope_DeniesMissingScope(t *testing.T) {
	if got := run(t, true, "openid monitoring:read", "monitoring:write"); got != http.StatusForbidden {
		t.Fatalf("missing scope: got %d, want 403", got)
	}
	if got := run(t, true, "openid", "admin"); got != http.StatusForbidden {
		t.Fatalf("monitoring client must not reach an admin-scoped route: got %d, want 403", got)
	}
}

func TestRequireScope_DeniesWhenNoClaims(t *testing.T) {
	h := RequireScope("monitoring:read", true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil)) // no claims in ctx
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no claims: got %d, want 403", rec.Code)
	}
}
