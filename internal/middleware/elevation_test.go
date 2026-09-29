// Package middleware — tests for RequireFreshAuth (Tier-0 admin step-up, PR4).
// Destructive admin routes require a recent authentication (auth_time within the
// window); otherwise the request is rejected with "elevation_required".
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

func runFresh(t *testing.T, maxAge time.Duration, claims *auth.AccessTokenClaims) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	next := false
	h := RequireFreshAuth(maxAge)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		next = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodDelete, "/api/admin/apps/1", nil)
	if claims != nil {
		r = r.WithContext(context.WithValue(r.Context(), contextkeys.JWTClaimsKey, claims))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr, next
}

func TestFreshAuth_RecentAuth_Passes(t *testing.T) {
	rr, next := runFresh(t, 5*time.Minute, &auth.AccessTokenClaims{AuthTime: time.Now().Add(-1 * time.Minute).Unix()})
	if rr.Code != http.StatusOK || !next {
		t.Errorf("recent auth_time should pass, got %d", rr.Code)
	}
}

func TestFreshAuth_StaleAuth_Blocks(t *testing.T) {
	rr, next := runFresh(t, 5*time.Minute, &auth.AccessTokenClaims{AuthTime: time.Now().Add(-10 * time.Minute).Unix()})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("stale auth_time should be 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "elevation_required") {
		t.Errorf("expected elevation_required, got %q", rr.Body.String())
	}
	if next {
		t.Error("handler must not run for a stale auth_time")
	}
}

func TestFreshAuth_NoClaims_Blocks(t *testing.T) {
	rr, _ := runFresh(t, 5*time.Minute, nil)
	if rr.Code != http.StatusForbidden {
		t.Errorf("missing claims should be 403, got %d", rr.Code)
	}
}

func TestFreshAuth_ZeroAuthTime_Blocks(t *testing.T) {
	rr, _ := runFresh(t, 5*time.Minute, &auth.AccessTokenClaims{AuthTime: 0})
	if rr.Code != http.StatusForbidden {
		t.Errorf("zero auth_time cannot prove freshness, want 403, got %d", rr.Code)
	}
}

func TestFreshAuth_Disabled_Passes(t *testing.T) {
	// maxAge <= 0 disables the gate even with a stale / absent auth_time.
	rr, next := runFresh(t, 0, &auth.AccessTokenClaims{AuthTime: time.Now().Add(-time.Hour).Unix()})
	if rr.Code != http.StatusOK || !next {
		t.Errorf("disabled gate should pass through, got %d", rr.Code)
	}
}
