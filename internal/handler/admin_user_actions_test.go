// Package handler — tests for the DeleteUser and BlockUser admin handlers.
//
// These tests verify the security guards (must be global admin, cannot target
// yourself, cannot delete/block superadmins via this endpoint) and the happy
// path for both actions.
package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// ---------------------------------------------------------------------------
// Minimal service stubs for AdminHandler
// ---------------------------------------------------------------------------

// adminTestUserService is a configurable stub for UserService used in
// DeleteUser / BlockUser handler tests.
type adminTestUserService struct {
	getByID func(ctx context.Context, id uint) (*model.User, error)
	delete  func(ctx context.Context, id uint) error
	block   func(ctx context.Context, id uint) error
}

func (s *adminTestUserService) GetByID(ctx context.Context, id uint) (*model.User, error) {
	if s.getByID != nil {
		return s.getByID(ctx, id)
	}
	panic("GetByID called unexpectedly")
}
func (s *adminTestUserService) Delete(ctx context.Context, id uint) error {
	if s.delete != nil {
		return s.delete(ctx, id)
	}
	panic("Delete called unexpectedly")
}
func (s *adminTestUserService) Block(ctx context.Context, id uint) error {
	if s.block != nil {
		return s.block(ctx, id)
	}
	panic("Block called unexpectedly")
}

// Remaining interface stubs — panic if called so tests are explicit.
func (s *adminTestUserService) List(_ context.Context, _, _ int) ([]model.User, int64, error) {
	panic("not implemented")
}
func (s *adminTestUserService) GetByEmail(_ context.Context, _ string) (*model.User, error) {
	panic("not implemented")
}
func (s *adminTestUserService) Create(_ context.Context, _ dto.CreateUserRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *adminTestUserService) Update(_ context.Context, _ uint, _ dto.UpdateUserRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *adminTestUserService) UpdateProfile(_ context.Context, _ uint, _ dto.UpdateProfileRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *adminTestUserService) VerifyEmail(_ context.Context, _ uint) error              { return nil }
func (s *adminTestUserService) UpdatePassword(_ context.Context, _ uint, _ string) error { return nil }
func (s *adminTestUserService) IncrementTokenVersion(_ context.Context, _ uint) error    { return nil }
func (s *adminTestUserService) RevokeTokens(_ context.Context, _ uint) error             { return nil }
func (s *adminTestUserService) Unlock(_ context.Context, _ uint) error                   { return nil }
func (s *adminTestUserService) ListSuperadmins(_ context.Context) ([]model.User, error)  { return nil, nil }
func (s *adminTestUserService) CountSuperadmins(_ context.Context) (int64, error)        { return 0, nil }
func (s *adminTestUserService) CreateSuperadmin(_ context.Context, _ dto.CreateSuperadminRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *adminTestUserService) UpdateSuperadmin(_ context.Context, _ uint, _ dto.UpdateSuperadminRequest) (*model.User, error) {
	panic("not implemented")
}
func (s *adminTestUserService) DeleteSuperadmin(_ context.Context, _ uint, _ uint) error {
	panic("not implemented")
}

// noopAdminLogService silently discards all log calls.
type noopAdminLogService struct{}

func (n *noopAdminLogService) LogAction(_ context.Context, _ uint, _ *uint, _ *uint, _ model.AdminAction, _ map[string]interface{}) error {
	return nil
}
func (n *noopAdminLogService) GetByAdmin(_ context.Context, _ uint, _, _ int) ([]model.AdminLog, int64, error) {
	return nil, 0, nil
}
func (n *noopAdminLogService) GetByApp(_ context.Context, _ uint, _, _ int) ([]model.AdminLog, int64, error) {
	return nil, 0, nil
}
func (n *noopAdminLogService) GetByDateRange(_ context.Context, _ uint, _, _ time.Time, _, _ int) ([]model.AdminLog, int64, error) {
	return nil, 0, nil
}

// panicAppService — AppService stub that panics on any call (unused by these tests).
type panicAppService struct{}

func (p *panicAppService) List(_ context.Context) ([]model.App, error)      { panic("not implemented") }
func (p *panicAppService) GetByID(_ context.Context, _ uint) (*model.App, error) {
	panic("not implemented")
}
func (p *panicAppService) GetByClientID(_ context.Context, _ string) (*model.App, error) {
	panic("not implemented")
}
func (p *panicAppService) GetByOwnerID(_ context.Context, _ uint) ([]model.App, error) {
	panic("not implemented")
}
func (p *panicAppService) Create(_ context.Context, _ dto.CreateAppRequest, _ uint) (*model.App, string, error) {
	panic("not implemented")
}
func (p *panicAppService) Update(_ context.Context, _ uint, _ dto.UpdateAppRequest) (*model.App, error) {
	panic("not implemented")
}
func (p *panicAppService) Delete(_ context.Context, _ uint) error { panic("not implemented") }
func (p *panicAppService) RotateSecret(_ context.Context, _ uint) (*model.App, string, error) {
	panic("not implemented")
}
func (p *panicAppService) ValidateClientCredentials(_ context.Context, _, _ string) (*model.App, error) {
	panic("not implemented")
}
func (p *panicAppService) GetAllAppURLs(_ context.Context) ([]string, error) {
	panic("not implemented")
}

// panicUserAppRoleService — UserAppRoleService stub that panics on any call.
type panicUserAppRoleService struct{}

func (p *panicUserAppRoleService) GetUserRoleForApp(_ context.Context, _, _ uint) (*model.UserAppRole, error) {
	panic("not implemented")
}
func (p *panicUserAppRoleService) GetUserRoles(_ context.Context, _ uint) ([]model.UserAppRole, error) {
	panic("not implemented")
}
func (p *panicUserAppRoleService) GetAppUsers(_ context.Context, _ uint, _, _ int, _ string) ([]model.UserAppRole, int64, error) {
	panic("not implemented")
}
func (p *panicUserAppRoleService) GetUserRolesMap(_ context.Context, _ uint) (map[string]string, error) {
	panic("not implemented")
}
func (p *panicUserAppRoleService) AssignRole(_ context.Context, _, _ uint, _ model.AppRole) (*model.UserAppRole, error) {
	panic("not implemented")
}
func (p *panicUserAppRoleService) UpdateRole(_ context.Context, _, _ uint, _ model.AppRole) (*model.UserAppRole, error) {
	panic("not implemented")
}
func (p *panicUserAppRoleService) RemoveRole(_ context.Context, _, _ uint) error {
	panic("not implemented")
}
func (p *panicUserAppRoleService) SetInviteSent(_ context.Context, _, _ uint) error {
	panic("not implemented")
}

// panicEmailService — EmailService stub that panics on any call.
type panicEmailService struct{}

func (p *panicEmailService) SendVerificationEmail(_, _, _, _ string) error      { panic("not implemented") }
func (p *panicEmailService) SendPasswordResetEmail(_, _, _, _ string) error     { panic("not implemented") }
func (p *panicEmailService) SendInvitationEmail(_, _, _, _, _ string) error     { panic("not implemented") }
func (p *panicEmailService) SendInviteEmail(_, _, _ string) error               { panic("not implemented") }
func (p *panicEmailService) SendWelcomeEmail(_, _, _ string) error              { panic("not implemented") }
func (p *panicEmailService) SendAppCredentialsEmail(_, _, _, _, _ string) error { panic("not implemented") }

// Compile-time interface checks.
var _ service.UserService        = (*adminTestUserService)(nil)
var _ service.AdminLogService    = (*noopAdminLogService)(nil)
var _ service.AppService         = (*panicAppService)(nil)
var _ service.UserAppRoleService = (*panicUserAppRoleService)(nil)
var _ service.EmailService       = (*panicEmailService)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestAdminHandler builds an AdminHandler wired with the supplied UserService stub.
func newTestAdminHandler(us service.UserService) *AdminHandler {
	return NewAdminHandler(
		&panicAppService{},
		us,
		&panicUserAppRoleService{},
		&noopAdminLogService{},
		nil, // AppActivityLogService — unused by these tests
		nil, // EmailService — unused by these tests
	)
}

// adminCtx returns a context that satisfies both GetUserIDFromContext (via
// contextkeys.UserIDKey) and the CurrentUser check (via contextkeys.CurrentUserKey).
func adminCtx(adminID uint, role model.UserRole) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.UserIDKey, adminID)
	ctx = context.WithValue(ctx, contextkeys.CurrentUserKey, &model.User{
		ID:   adminID,
		Role: role,
	})
	return ctx
}

// chiCtxWithID wraps a request in a chi context that exposes {id} as a URL param.
func chiCtxWithID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// regularUser returns a plain user (role=user) with the given ID.
func regularUser(id uint) *model.User {
	return &model.User{ID: id, Email: "user@example.com", Role: model.UserRoleUser}
}

// superadminUser returns a superadmin user with the given ID.
func superadminUser(id uint) *model.User {
	return &model.User{ID: id, Email: "super@example.com", Role: model.UserRoleSuperadmin}
}

// ---------------------------------------------------------------------------
// DeleteUser tests
// ---------------------------------------------------------------------------

func TestDeleteUser_HappyPath(t *testing.T) {
	const (
		adminID  = uint(1)
		targetID = uint(2)
	)

	deleted := false
	us := &adminTestUserService{
		getByID: func(_ context.Context, id uint) (*model.User, error) {
			return regularUser(id), nil
		},
		delete: func(_ context.Context, id uint) error {
			if id != targetID {
				t.Errorf("Delete: unexpected id %d", id)
			}
			deleted = true
			return nil
		},
	}

	h := newTestAdminHandler(us)
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/2", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "2")
	rr := httptest.NewRecorder()

	h.DeleteUser(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !deleted {
		t.Error("expected userService.Delete to be called")
	}
}

func TestDeleteUser_RequiresGlobalAdmin(t *testing.T) {
	// A plain user (role=user) must receive 403.
	us := &adminTestUserService{}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/2", nil)
	req = req.WithContext(adminCtx(1, model.UserRoleUser))
	req = chiCtxWithID(req, "2")
	rr := httptest.NewRecorder()

	h.DeleteUser(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestDeleteUser_CannotDeleteSelf(t *testing.T) {
	// Admin trying to delete their own account must receive 400.
	const adminID = uint(1)
	us := &adminTestUserService{}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/1", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "1") // same ID as adminID
	rr := httptest.NewRecorder()

	h.DeleteUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestDeleteUser_CannotDeleteSuperadmin(t *testing.T) {
	// Deleting a superadmin via this endpoint must return 403; the caller must
	// use DELETE /api/admin/superadmins/:id instead.
	const (
		adminID  = uint(1)
		targetID = uint(99)
	)

	us := &adminTestUserService{
		getByID: func(_ context.Context, _ uint) (*model.User, error) {
			return superadminUser(targetID), nil
		},
	}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/99", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "99")
	rr := httptest.NewRecorder()

	h.DeleteUser(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestDeleteUser_UserNotFound(t *testing.T) {
	const adminID = uint(1)

	us := &adminTestUserService{
		getByID: func(_ context.Context, _ uint) (*model.User, error) {
			return nil, errors.New("not found")
		},
	}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/404", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "404")
	rr := httptest.NewRecorder()

	h.DeleteUser(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestDeleteUser_InvalidID(t *testing.T) {
	us := &adminTestUserService{}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/notanumber", nil)
	req = req.WithContext(adminCtx(1, model.UserRoleAdmin))
	req = chiCtxWithID(req, "notanumber")
	rr := httptest.NewRecorder()

	h.DeleteUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestDeleteUser_ServiceError(t *testing.T) {
	const (
		adminID  = uint(1)
		targetID = uint(2)
	)

	us := &adminTestUserService{
		getByID: func(_ context.Context, id uint) (*model.User, error) {
			return regularUser(id), nil
		},
		delete: func(_ context.Context, _ uint) error {
			return errors.New("db error")
		},
	}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/2", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "2")
	rr := httptest.NewRecorder()

	h.DeleteUser(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// BlockUser tests
// ---------------------------------------------------------------------------

func TestBlockUser_HappyPath(t *testing.T) {
	const (
		adminID  = uint(1)
		targetID = uint(2)
	)

	blocked := false
	us := &adminTestUserService{
		getByID: func(_ context.Context, id uint) (*model.User, error) {
			return regularUser(id), nil
		},
		block: func(_ context.Context, id uint) error {
			if id != targetID {
				t.Errorf("Block: unexpected id %d", id)
			}
			blocked = true
			return nil
		},
	}

	h := newTestAdminHandler(us)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/2/block", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "2")
	rr := httptest.NewRecorder()

	h.BlockUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !blocked {
		t.Error("expected userService.Block to be called")
	}
}

func TestBlockUser_RequiresGlobalAdmin(t *testing.T) {
	us := &adminTestUserService{}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/2/block", nil)
	req = req.WithContext(adminCtx(1, model.UserRoleUser))
	req = chiCtxWithID(req, "2")
	rr := httptest.NewRecorder()

	h.BlockUser(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestBlockUser_CannotBlockSelf(t *testing.T) {
	const adminID = uint(1)
	us := &adminTestUserService{}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/1/block", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "1")
	rr := httptest.NewRecorder()

	h.BlockUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestBlockUser_UserNotFound(t *testing.T) {
	const adminID = uint(1)

	us := &adminTestUserService{
		getByID: func(_ context.Context, _ uint) (*model.User, error) {
			return nil, errors.New("not found")
		},
	}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/404/block", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "404")
	rr := httptest.NewRecorder()

	h.BlockUser(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestBlockUser_ServiceRejectsSuperadmin(t *testing.T) {
	// The service's Block() method itself refuses superadmins; the handler
	// surfaces this as a 400 Bad Request.
	const (
		adminID  = uint(1)
		targetID = uint(99)
	)

	us := &adminTestUserService{
		getByID: func(_ context.Context, id uint) (*model.User, error) {
			return regularUser(id), nil // returns a regular user to pass handler check
		},
		block: func(_ context.Context, _ uint) error {
			return errors.New("cannot block a superadmin; remove the account instead")
		},
	}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/99/block", nil)
	req = req.WithContext(adminCtx(adminID, model.UserRoleAdmin))
	req = chiCtxWithID(req, "99")
	rr := httptest.NewRecorder()

	h.BlockUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestBlockUser_InvalidID(t *testing.T) {
	us := &adminTestUserService{}
	h := newTestAdminHandler(us)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/xyz/block", nil)
	req = req.WithContext(adminCtx(1, model.UserRoleAdmin))
	req = chiCtxWithID(req, "xyz")
	rr := httptest.NewRecorder()

	h.BlockUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
