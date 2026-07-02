// Package middleware — regression test for audit finding H1.
//
// H1: app-scoped user management (/api/apps/{app_id}/users …) was gated only by
// RequireAppAccess, which passes for ANY role in the app (viewer/user/admin).
// That let any app member create users, escalate roles to admin, remove users,
// and force password resets within their tenant — an intra-tenant privilege
// escalation / broken-access-control bug.
//
// Fix: the /users subtree is now gated with RequireAppAdmin (matching the
// existing /logs precedent). These tests wire RequireAppAdmin the same way the
// router does — around the mutating user handlers, with the {app_id} URL param
// extracted by chi — and prove that a non-admin app member is rejected with 403
// while an app admin reaches the handler.
package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
)

// h1FakeRoleRepo is a minimal UserAppRoleRepository stand-in. Only
// FindByUserAndApp is exercised by RequireAppAdmin; the rest satisfy the
// interface and are never called in these tests.
type h1FakeRoleRepo struct {
	role *model.UserAppRole // returned by FindByUserAndApp; nil => notFound error
}

func (f *h1FakeRoleRepo) FindByUserAndApp(_ context.Context, _, _ uint) (*model.UserAppRole, error) {
	if f.role == nil {
		return nil, errors.New("record not found")
	}
	return f.role, nil
}

func (f *h1FakeRoleRepo) FindByUser(context.Context, uint) ([]model.UserAppRole, error) {
	return nil, nil
}
func (f *h1FakeRoleRepo) FindByApp(context.Context, uint, int, int, string) ([]model.UserAppRole, int64, error) {
	return nil, 0, nil
}
func (f *h1FakeRoleRepo) FindAllByUser(context.Context, uint) ([]model.UserAppRole, error) {
	return nil, nil
}
func (f *h1FakeRoleRepo) Create(context.Context, *model.UserAppRole) error { return nil }
func (f *h1FakeRoleRepo) Update(context.Context, *model.UserAppRole) error { return nil }
func (f *h1FakeRoleRepo) Delete(context.Context, uint, uint) error         { return nil }
func (f *h1FakeRoleRepo) GetUserRolesMap(context.Context, uint) (map[string]string, error) {
	return nil, nil
}

var _ repository.UserAppRoleRepository = (*h1FakeRoleRepo)(nil)

// h1Router builds a chi router mirroring the production wiring of the
// app-scoped /users subtree: RequireAppAdmin guards the mutating handlers.
// The reached handler writes 200 so tests can distinguish "gate passed"
// (200 — reached handler) from "gate blocked" (403).
func h1Router(repo repository.UserAppRoleRepository) http.Handler {
	reached := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := chi.NewRouter()
	r.Route("/api/apps/{app_id}", func(r chi.Router) {
		r.Route("/users", func(r chi.Router) {
			r.Use(RequireAppAdmin(repo))
			r.Post("/", reached)         // CreateUser
			r.Put("/{user_id}", reached) // UpdateUserRole
		})
	})
	return r
}

// h1Request builds a request as an authenticated app member: UserIDKey and
// CurrentUserKey are populated the way AuthMiddleware would, so RequireAppAdmin
// can resolve the caller. globalRole controls whether the user is a global
// admin (which legitimately bypasses per-app checks).
func h1Request(method, path string, globalRole model.UserRole) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), contextkeys.UserIDKey, uint(42))
	ctx = context.WithValue(ctx, contextkeys.CurrentUserKey, &model.User{Role: globalRole})
	return req.WithContext(ctx)
}

func h1Serve(t *testing.T, repo repository.UserAppRoleRepository, method, path string, globalRole model.UserRole) int {
	t.Helper()
	rr := httptest.NewRecorder()
	h1Router(repo).ServeHTTP(rr, h1Request(method, path, globalRole))
	return rr.Code
}

// TestH1_ViewerCannotCreateUser proves a non-admin app member (viewer) is
// rejected with 403 on CreateUser — the core H1 regression.
func TestH1_ViewerCannotCreateUser(t *testing.T) {
	repo := &h1FakeRoleRepo{role: &model.UserAppRole{UserID: 42, AppID: 7, Role: model.AppRoleViewer}}
	if got := h1Serve(t, repo, http.MethodPost, "/api/apps/7/users/", model.UserRoleUser); got != http.StatusForbidden {
		t.Fatalf("H1: viewer POST /users must be 403, got %d", got)
	}
}

// TestH1_UserRoleCannotEscalateViaUpdateRole proves a plain "user" app member
// cannot reach UpdateUserRole (the privilege-escalation-to-admin vector).
func TestH1_UserRoleCannotEscalateViaUpdateRole(t *testing.T) {
	repo := &h1FakeRoleRepo{role: &model.UserAppRole{UserID: 42, AppID: 7, Role: model.AppRoleUser}}
	if got := h1Serve(t, repo, http.MethodPut, "/api/apps/7/users/99", model.UserRoleUser); got != http.StatusForbidden {
		t.Fatalf("H1: non-admin PUT /users/{id} must be 403, got %d", got)
	}
}

// TestH1_NonMemberRejected proves a user with no role row in the target app
// (and no global-admin status) is rejected — cross-tenant protection preserved.
func TestH1_NonMemberRejected(t *testing.T) {
	repo := &h1FakeRoleRepo{role: nil} // FindByUserAndApp returns not-found
	if got := h1Serve(t, repo, http.MethodPost, "/api/apps/7/users/", model.UserRoleUser); got != http.StatusForbidden {
		t.Fatalf("H1: non-member POST /users must be 403, got %d", got)
	}
}

// TestH1_AppAdminCanCreateUser proves the fix is not over-broad: an app admin
// passes the gate and reaches the handler (200).
func TestH1_AppAdminCanCreateUser(t *testing.T) {
	repo := &h1FakeRoleRepo{role: &model.UserAppRole{UserID: 42, AppID: 7, Role: model.AppRoleAdmin}}
	if got := h1Serve(t, repo, http.MethodPost, "/api/apps/7/users/", model.UserRoleUser); got != http.StatusOK {
		t.Fatalf("H1: app-admin POST /users must reach handler (200), got %d", got)
	}
}

// TestH1_AppAdminCanUpdateRole proves an app admin reaches UpdateUserRole.
func TestH1_AppAdminCanUpdateRole(t *testing.T) {
	repo := &h1FakeRoleRepo{role: &model.UserAppRole{UserID: 42, AppID: 7, Role: model.AppRoleAdmin}}
	if got := h1Serve(t, repo, http.MethodPut, "/api/apps/7/users/99", model.UserRoleUser); got != http.StatusOK {
		t.Fatalf("H1: app-admin PUT /users/{id} must reach handler (200), got %d", got)
	}
}

// TestH1_GlobalAdminBypass proves a global admin (no per-app row) still reaches
// the handler — RequireAppAdmin intentionally lets global admins through.
func TestH1_GlobalAdminBypass(t *testing.T) {
	repo := &h1FakeRoleRepo{role: nil} // no per-app row for global admins
	if got := h1Serve(t, repo, http.MethodPost, "/api/apps/7/users/", model.UserRoleAdmin); got != http.StatusOK {
		t.Fatalf("H1: global admin POST /users must reach handler (200), got %d", got)
	}
}
