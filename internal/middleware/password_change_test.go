// Package middleware — tests for RequirePasswordChangeComplete (Tier-0 admin
// session hardening, PR3). An admin flagged MustChangePassword is blocked from
// protected routes (403 password_change_required) until they change it; the
// change-password path is exempt.
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
)

func runPwGuard(t *testing.T, path string, user *model.User, exempt ...string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	nextCalled := false
	h := RequirePasswordChangeComplete(exempt...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if user != nil {
		r = r.WithContext(context.WithValue(r.Context(), contextkeys.CurrentUserKey, user))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr, nextCalled
}

func TestPwGuard_Flagged_Blocks(t *testing.T) {
	rr, next := runPwGuard(t, "/api/admin/apps", &model.User{MustChangePassword: true})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("flagged user should get 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "password_change_required") {
		t.Errorf("expected machine-readable code password_change_required, got %q", rr.Body.String())
	}
	if next {
		t.Error("downstream handler must not run for a flagged user")
	}
}

func TestPwGuard_Flagged_ExemptPathPasses(t *testing.T) {
	rr, next := runPwGuard(t, "/api/admin/change-password", &model.User{MustChangePassword: true}, "/change-password")
	if rr.Code != http.StatusOK || !next {
		t.Errorf("exempt path must pass through even when flagged, got %d", rr.Code)
	}
}

func TestPwGuard_NotFlagged_Passes(t *testing.T) {
	rr, next := runPwGuard(t, "/api/admin/apps", &model.User{MustChangePassword: false})
	if rr.Code != http.StatusOK || !next {
		t.Errorf("unflagged user must pass, got %d", rr.Code)
	}
}

func TestPwGuard_NoUser_Passes(t *testing.T) {
	// Defensive: without a user in context (guard mis-ordered) it does not block;
	// AuthMiddleware is responsible for rejecting unauthenticated requests.
	rr, _ := runPwGuard(t, "/api/admin/apps", nil)
	if rr.Code != http.StatusOK {
		t.Errorf("no-user case should not 403 here, got %d", rr.Code)
	}
}
