package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// P3-7: the mail-triggering admin actions (resend-verification, force
// password reset) must be limited to members of the app being administered.
// P2-2: app_users_handler must not echo err.Error() to the caller.

type p37UserService struct {
	service.UserService
}

func (s *p37UserService) GetByID(_ context.Context, id uint) (*model.User, error) {
	return &model.User{ID: id, Email: fmt.Sprintf("u%d@example.com", id), Name: "U"}, nil
}

// p37RoleService reports membership for exactly one (user, app) pair and
// records whether the handler got past the membership gate.
type p37RoleService struct {
	panicUserAppRoleService
	memberUser, memberApp uint
	listErr               error
	updateErr             error
	removeErr             error
}

func (s *p37RoleService) GetUserRoleForApp(_ context.Context, userID, appID uint) (*model.UserAppRole, error) {
	if userID == s.memberUser && appID == s.memberApp {
		return &model.UserAppRole{UserID: userID, AppID: appID, Role: model.AppRoleUser}, nil
	}
	return nil, service.ErrRoleNotFound
}
func (s *p37RoleService) GetAppUsers(_ context.Context, _ uint, _, _ int, _ string) ([]model.UserAppRole, int64, error) {
	return nil, 0, s.listErr
}
func (s *p37RoleService) UpdateRole(_ context.Context, _, _ uint, _ model.AppRole) (*model.UserAppRole, error) {
	return nil, s.updateErr
}
func (s *p37RoleService) RemoveRole(_ context.Context, _, _ uint) error { return s.removeErr }

// p37AppService returns an app for GetByID and records that it was reached —
// GetByID is the first call after the membership gate.
type p37AppService struct {
	panicAppService
	reached bool
}

func (s *p37AppService) GetByID(_ context.Context, id uint) (*model.App, error) {
	s.reached = true
	return &model.App{ID: id, Name: "App"}, nil
}

func p37Request(method, path string, appID, userID uint, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), contextkeys.UserIDKey, uint(1))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("app_id", fmt.Sprint(appID))
	rctx.URLParams.Add("user_id", fmt.Sprint(userID))
	return req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
}

func TestP37_MailActions_RejectNonMembers(t *testing.T) {
	const app, member, outsider = uint(1), uint(5), uint(99)
	actions := []struct {
		name string
		call func(h *AppUsersHandler, w http.ResponseWriter, r *http.Request)
	}{
		{"resend-verification", (*AppUsersHandler).ResendVerification},
		{"reset-password", (*AppUsersHandler).ForcePasswordReset},
	}
	for _, a := range actions {
		roles := &p37RoleService{memberUser: member, memberApp: app}
		apps := &p37AppService{}
		// tokenService nil: the handler must never reach token generation for
		// an outsider (it would nil-deref and fail the test loudly).
		h := NewAppUsersHandler(&p37UserService{}, roles, apps, &noopAdminLogService{}, nil, nil, "https://auth.example")

		rr := httptest.NewRecorder()
		a.call(h, rr, p37Request(http.MethodPost, "/api/apps/1/users/99/"+a.name, app, outsider, ""))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: outsider got %d, want 404", a.name, rr.Code)
		}
		if apps.reached {
			t.Errorf("%s: handler proceeded past the membership gate for an outsider", a.name)
		}
		if strings.Contains(rr.Body.String(), "u99@example.com") {
			t.Errorf("%s: response disclosed the foreign user's email", a.name)
		}
	}
}

func TestP37_MailActions_AllowMembers(t *testing.T) {
	const app, member = uint(1), uint(5)
	for _, name := range []string{"resend-verification", "reset-password"} {
		roles := &p37RoleService{memberUser: member, memberApp: app}
		apps := &p37AppService{}
		h := NewAppUsersHandler(&p37UserService{}, roles, apps, &noopAdminLogService{}, nil, nil, "https://auth.example")
		call := (*AppUsersHandler).ResendVerification
		if name == "reset-password" {
			call = (*AppUsersHandler).ForcePasswordReset
		}
		rr := httptest.NewRecorder()
		// tokenService is nil, so a member request panics at token generation —
		// that is after the gate, which is all this test asserts.
		func() {
			defer func() { _ = recover() }()
			call(h, rr, p37Request(http.MethodPost, "/api/apps/1/users/5/"+name, app, member, ""))
		}()
		if !apps.reached {
			t.Errorf("%s: member was blocked by the membership gate", name)
		}
	}
}

func TestP22_AppUsers_DoNotEchoInternalErrors(t *testing.T) {
	internal := errors.New(`pq: relation "user_app_roles" does not exist (SQLSTATE 42P01)`)
	roles := &p37RoleService{listErr: internal, updateErr: internal, removeErr: internal}
	h := NewAppUsersHandler(&p37UserService{}, roles, &p37AppService{}, &noopAdminLogService{}, nil, nil, "https://auth.example")

	cases := []struct {
		name string
		run  func(w http.ResponseWriter)
	}{
		{"list", func(w http.ResponseWriter) {
			h.ListUsers(w, p37Request(http.MethodGet, "/api/apps/1/users", 1, 0, ""))
		}},
		{"update-role", func(w http.ResponseWriter) {
			h.UpdateUserRole(w, p37Request(http.MethodPut, "/api/apps/1/users/5", 1, 5, `{"role":"viewer"}`))
		}},
		{"remove", func(w http.ResponseWriter) {
			h.RemoveUser(w, p37Request(http.MethodDelete, "/api/apps/1/users/5", 1, 5, ""))
		}},
	}
	for _, c := range cases {
		rr := httptest.NewRecorder()
		c.run(rr)
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d, want 500", c.name, rr.Code)
		}
		for _, leak := range []string{"pq:", "SQLSTATE", "user_app_roles"} {
			if strings.Contains(rr.Body.String(), leak) {
				t.Errorf("%s: response leaked %q: %s", c.name, leak, rr.Body.String())
			}
		}
	}
}

func TestP22_AppUsers_RoleNotFoundIs404(t *testing.T) {
	roles := &p37RoleService{updateErr: service.ErrRoleNotFound, removeErr: service.ErrRoleNotFound}
	h := NewAppUsersHandler(&p37UserService{}, roles, &p37AppService{}, &noopAdminLogService{}, nil, nil, "https://auth.example")

	rr := httptest.NewRecorder()
	h.UpdateUserRole(rr, p37Request(http.MethodPut, "/api/apps/1/users/5", 1, 5, `{"role":"viewer"}`))
	if rr.Code != http.StatusNotFound {
		t.Errorf("update: status %d, want 404", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.RemoveUser(rr, p37Request(http.MethodDelete, "/api/apps/1/users/5", 1, 5, ""))
	if rr.Code != http.StatusNotFound {
		t.Errorf("remove: status %d, want 404", rr.Code)
	}
}
