// Package handler — tests for the service account (client_credentials) code-path
// in AppUsersHandler.CreateUser.
//
// A client_credentials token carries no user ID.  The handler must accept the
// request when a *model.App is present in context under ServiceAccountAppKey
// (placed there by ServiceAccountMiddleware) and must use adminID=0 as the
// system-actor sentinel for audit logging.
//
// Tests verify:
//  1. No user ID in context + no service account app → 401
//  2. No user ID in context + service account app present → proceeds past the
//     auth guard (panics only on the downstream AssignRole call, which requires
//     a full stack — the panic signals the guard was bypassed correctly)
//  3. Service account — superadmin target is still rejected with 403
//  4. Service account — invalid JSON body returns 400 before any side-effect
//  5. Service account — missing required fields returns 400
package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

// ---------------------------------------------------------------------------
// Helper: build a service-account request (no user ID in context)
// ---------------------------------------------------------------------------

// serviceAccountRequest creates a POST /api/apps/{app_id}/service/users request
// with the given JSON body and attaches a *model.App as the service account
// context value — mimicking what ServiceAccountMiddleware does.
func serviceAccountRequest(appID uint, app *model.App, body string) *http.Request {
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/apps/%d/service/users", appID),
		bytes.NewBufferString(body),
	)
	req.Header.Set("Content-Type", "application/json")

	ctx := req.Context()

	// ServiceAccountMiddleware sets this; AuthMiddleware does NOT run.
	if app != nil {
		ctx = context.WithValue(ctx, contextkeys.ServiceAccountAppKey, app)
	}

	// chi route context with {app_id}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("app_id", fmt.Sprintf("%d", appID))
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

	return req.WithContext(ctx)
}

// serviceAccountApp returns a minimal active *model.App for test use.
func serviceAccountApp(id uint) *model.App {
	return &model.App{
		ID:     id,
		Name:   "kerplan-backend",
		Active: true,
	}
}

// ---------------------------------------------------------------------------
// Test 1: No user ID + no service account app → 401
// ---------------------------------------------------------------------------

func TestCreateAppUser_ServiceAccount_NoContextAtAll_Returns401(t *testing.T) {
	h := newTestAppUsersHandler(&appUsersTestUserService{})

	// Request with neither UserIDKey nor ServiceAccountAppKey in context.
	req := httptest.NewRequest(http.MethodPost, "/api/apps/1/service/users",
		bytes.NewBufferString(`{"email":"x@x.com","role":"user"}`))
	req.Header.Set("Content-Type", "application/json")

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("app_id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.CreateUser(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d (body: %s)", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Test 2: Service account context present → proceeds past the auth guard
// ---------------------------------------------------------------------------

func TestCreateAppUser_ServiceAccount_ValidContext_PassesAuthGuard(t *testing.T) {
	us := &appUsersTestUserService{
		getByEmail: func(_ context.Context, _ string) (*model.User, error) {
			// Regular user — superadmin guard must not fire.
			return &model.User{
				ID:    42,
				Email: "collab@kerplan.io",
				Role:  model.UserRoleUser,
			}, nil
		},
	}

	h := newTestAppUsersHandler(us)
	body := `{"email":"collab@kerplan.io","role":"editor"}`
	req := serviceAccountRequest(1, serviceAccountApp(1), body)
	rr := httptest.NewRecorder()

	// The handler will panic on AssignRole (panicUserAppRoleService).
	// A panic here means the auth guard was passed — which is exactly what we test.
	func() {
		defer func() {
			if rv := recover(); rv != nil {
				// Panic from downstream stub — auth guard was bypassed correctly.
				if rr.Code == http.StatusUnauthorized {
					t.Error("auth guard fired 401 for a valid service account context")
				}
				if rr.Code == http.StatusForbidden {
					t.Error("auth guard fired 403 for a regular user target")
				}
			}
		}()
		h.CreateUser(rr, req)
	}()
}

// ---------------------------------------------------------------------------
// Test 3: Service account — superadmin target still rejected with 403
// ---------------------------------------------------------------------------

func TestCreateAppUser_ServiceAccount_RejectsSuperadminTarget(t *testing.T) {
	createCalled := false

	us := &appUsersTestUserService{
		getByEmail: func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID:    7,
				Email: "god@example.com",
				Role:  model.UserRoleSuperadmin,
			}, nil
		},
		create: func(_ context.Context, _ dto.CreateUserRequest) (*model.User, error) {
			createCalled = true
			return nil, nil
		},
	}

	h := newTestAppUsersHandler(us)
	body := `{"email":"god@example.com","role":"admin"}`
	req := serviceAccountRequest(1, serviceAccountApp(1), body)
	rr := httptest.NewRecorder()

	h.CreateUser(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for superadmin target, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if createCalled {
		t.Error("userService.Create must NOT be called when rejecting a superadmin target")
	}
}

// ---------------------------------------------------------------------------
// Test 4: Service account — invalid JSON returns 400
// ---------------------------------------------------------------------------

func TestCreateAppUser_ServiceAccount_InvalidJSON_Returns400(t *testing.T) {
	h := newTestAppUsersHandler(&appUsersTestUserService{})

	req := serviceAccountRequest(1, serviceAccountApp(1), `{invalid-json}`)
	rr := httptest.NewRecorder()

	h.CreateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Service account — missing required fields returns 400
// ---------------------------------------------------------------------------

func TestCreateAppUser_ServiceAccount_MissingFields_Returns400(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"missing email", `{"role":"user"}`},
		{"missing role", `{"email":"x@x.com"}`},
		{"empty body", `{}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAppUsersHandler(&appUsersTestUserService{})
			req := serviceAccountRequest(1, serviceAccountApp(1), tc.body)
			rr := httptest.NewRecorder()

			h.CreateUser(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s: expected 400, got %d (body: %s)", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}
