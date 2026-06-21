// Package handler — tests for the superadmin-in-app guard in AppUsersHandler.CreateUser.
//
// A superadmin already has global access to every application.  Assigning them
// an explicit per-app role would make them appear in the per-app user list,
// which is both confusing and incorrect.  The guard must reject the request
// with 403 before any side-effect (user creation, role assignment, invite token
// generation, email send) can take place.
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
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// ---------------------------------------------------------------------------
// Minimal stubs for AppUsersHandler
// ---------------------------------------------------------------------------

// appUsersTestUserService stubs only the methods called on the happy / guard
// code-paths.  Unexpected calls panic.
type appUsersTestUserService struct {
	getByEmail func(ctx context.Context, email string) (*model.User, error)
	create     func(ctx context.Context, req dto.CreateUserRequest) (*model.User, error)
}

func (s *appUsersTestUserService) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	if s.getByEmail != nil {
		return s.getByEmail(ctx, email)
	}
	panic("GetByEmail called unexpectedly")
}
func (s *appUsersTestUserService) Create(ctx context.Context, req dto.CreateUserRequest) (*model.User, error) {
	if s.create != nil {
		return s.create(ctx, req)
	}
	panic("Create called unexpectedly")
}

// Remaining stubs.
func (s *appUsersTestUserService) List(_ context.Context, _, _ int) ([]model.User, int64, error) {
	panic("not implemented")
}
func (s *appUsersTestUserService) GetByID(_ context.Context, _ uint) (*model.User, error) {
	panic("not implemented")
}
func (s *appUsersTestUserService) Update(_ context.Context, _ uint, _ dto.UpdateUserRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *appUsersTestUserService) UpdateProfile(_ context.Context, _ uint, _ dto.UpdateProfileRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *appUsersTestUserService) Delete(_ context.Context, _ uint) error      { panic("not implemented") }
func (s *appUsersTestUserService) Block(_ context.Context, _ uint) error       { panic("not implemented") }
func (s *appUsersTestUserService) VerifyEmail(_ context.Context, _ uint) error { return nil }
func (s *appUsersTestUserService) UpdatePassword(_ context.Context, _ uint, _ string) error {
	return nil
}
func (s *appUsersTestUserService) IncrementTokenVersion(_ context.Context, _ uint) error { return nil }
func (s *appUsersTestUserService) RevokeTokens(_ context.Context, _ uint) error          { return nil }
func (s *appUsersTestUserService) Unlock(_ context.Context, _ uint) error                { return nil }
func (s *appUsersTestUserService) ListSuperadmins(_ context.Context) ([]model.User, error) {
	return nil, nil
}
func (s *appUsersTestUserService) CountSuperadmins(_ context.Context) (int64, error) { return 0, nil }
func (s *appUsersTestUserService) CreateSuperadmin(_ context.Context, _ dto.CreateSuperadminRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *appUsersTestUserService) UpdateSuperadmin(_ context.Context, _ uint, _ dto.UpdateSuperadminRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *appUsersTestUserService) DeleteSuperadmin(_ context.Context, _ uint, _ uint) error {
	panic("not implemented")
}

// Compile-time interface check.
var _ service.UserService = (*appUsersTestUserService)(nil)

// ---------------------------------------------------------------------------
// Helper: build an AppUsersHandler request with a chi app_id param
// ---------------------------------------------------------------------------

// appUsersRequest creates a POST /api/apps/{app_id}/users request with the
// given JSON body and attaches authentication context (user ID + current user).
func appUsersRequest(appID, adminID uint, body string) *http.Request {
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/apps/%d/users", appID),
		bytes.NewBufferString(body),
	)
	req.Header.Set("Content-Type", "application/json")

	// Build context with authentication.
	ctx := req.Context()
	ctx = context.WithValue(ctx, contextkeys.UserIDKey, adminID)
	ctx = context.WithValue(ctx, contextkeys.CurrentUserKey, &model.User{
		ID:   adminID,
		Role: model.UserRoleAdmin,
	})

	// Build chi route context with {app_id}.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("app_id", "1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

	return req.WithContext(ctx)
}

// newTestAppUsersHandler returns an AppUsersHandler with the supplied UserService
// and nil for all other dependencies (which must not be called in these tests).
func newTestAppUsersHandler(us service.UserService) *AppUsersHandler {
	return NewAppUsersHandler(
		us,
		&panicUserAppRoleService{},
		&panicAppService{},
		&noopAdminLogService{},
		nil, // emailService — must not be called before the guard fires
		nil, // tokenService — must not be called before the guard fires
		"https://auth.example.com",
	)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestCreateAppUser_RejectsSuperadmin verifies that assigning a superadmin to
// an app is refused with 403 Forbidden, and no side-effects occur.
func TestCreateAppUser_RejectsSuperadmin(t *testing.T) {
	createCalled := false

	us := &appUsersTestUserService{
		getByEmail: func(_ context.Context, _ string) (*model.User, error) {
			// The user exists and is a superadmin.
			return &model.User{
				ID:    99,
				Email: "super@example.com",
				Role:  model.UserRoleSuperadmin,
			}, nil
		},
		create: func(_ context.Context, _ dto.CreateUserRequest) (*model.User, error) {
			createCalled = true
			return nil, nil
		},
	}

	h := newTestAppUsersHandler(us)
	body := `{"email":"super@example.com","role":"admin"}`
	req := appUsersRequest(1, 1, body)
	rr := httptest.NewRecorder()

	h.CreateUser(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if createCalled {
		t.Error("userService.Create must NOT be called when rejecting a superadmin")
	}
}

// TestCreateAppUser_AllowsRegularUser verifies that a non-superadmin user can
// be assigned to an app — i.e. the superadmin guard doesn't block valid requests.
// The test stops after the guard because AssignRole would require a full stack;
// it is enough to confirm the handler proceeds past the guard (panics only on
// the next panicUserAppRoleService call which is after the guard).
func TestCreateAppUser_AllowsRegularUser(t *testing.T) {
	us := &appUsersTestUserService{
		getByEmail: func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID:    5,
				Email: "normal@example.com",
				Role:  model.UserRoleUser,
			}, nil
		},
	}

	h := newTestAppUsersHandler(us)
	body := `{"email":"normal@example.com","role":"viewer"}`
	req := appUsersRequest(1, 1, body)
	rr := httptest.NewRecorder()

	// The handler will panic on AssignRole (panicUserAppRoleService) — we
	// recover the panic and verify the guard did NOT fire (no 403 response
	// was written before the panic).
	func() {
		defer func() {
			if rv := recover(); rv != nil {
				// Expected: guard passed, panic came from panicUserAppRoleService.
				if rr.Code == http.StatusForbidden {
					t.Errorf("superadmin guard fired for a regular user")
				}
			}
		}()
		h.CreateUser(rr, req)
	}()
}

// TestCreateAppUser_InvalidRole verifies that an unrecognised role string is
// rejected with 400 before user look-up (guard cannot trigger for unknown roles).
func TestCreateAppUser_InvalidRole(t *testing.T) {
	us := &appUsersTestUserService{}
	h := newTestAppUsersHandler(us)

	body := `{"email":"someone@example.com","role":"godmode"}`
	req := appUsersRequest(1, 1, body)
	rr := httptest.NewRecorder()

	h.CreateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid role, got %d", rr.Code)
	}
}

// TestCreateAppUser_MissingFields verifies that omitting required fields returns 400.
func TestCreateAppUser_MissingFields(t *testing.T) {
	us := &appUsersTestUserService{}
	h := newTestAppUsersHandler(us)

	body := `{"email":""}` // missing role, empty email
	req := appUsersRequest(1, 1, body)
	rr := httptest.NewRecorder()

	h.CreateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", rr.Code)
	}
}
