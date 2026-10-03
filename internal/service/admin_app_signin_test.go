package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// ADMIN_APP_SIGNIN_POLICY: a Socrate admin or superadmin signs in to the
// operator consoles only. The rule is applied where an admin's implicit app
// role is granted: hosted login, code issuance and the refresh grant.

// adminAppAudit records the admin_app_signin rows only.
type adminAppAudit struct {
	repository.SecurityAuditLogRepository
	rows []*model.SecurityAuditLog
}

func (a *adminAppAudit) Create(_ context.Context, log *model.SecurityAuditLog) error {
	if log.EventType == model.SecurityEventAdminAppSignIn {
		a.rows = append(a.rows, log)
	}
	return nil
}

func TestAdminAppSignInPolicy_Decision(t *testing.T) {
	admin := &model.User{Role: model.UserRoleAdmin}
	super := &model.User{Role: model.UserRoleSuperadmin}
	member := &model.User{Role: model.UserRoleUser}
	console := &model.App{ClientID: "admin-bff"}
	gpwa := &model.App{ClientID: "gpwa"}

	enforce := NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"", "admin-bff", "monitoring-bff"})
	cases := []struct {
		name string
		p    AdminAppSignInPolicy
		user *model.User
		app  *model.App
		want bool
	}{
		{"superadmin on an app", enforce, super, gpwa, true},
		{"admin on an app", enforce, admin, gpwa, true},
		{"superadmin on a console", enforce, super, console, false},
		{"ordinary user", enforce, member, gpwa, false},
		{"policy off", NewAdminAppSignInPolicy(AdminAppSignInOff, nil), super, gpwa, false},
		{"zero value is off", AdminAppSignInPolicy{}, super, gpwa, false},
		{"unknown mode is off", NewAdminAppSignInPolicy("enforced", nil), super, gpwa, false},
	}
	for _, c := range cases {
		if got := c.p.outsideConsoles(c.user, c.app); got != c.want {
			t.Errorf("%s: outsideConsoles = %v, want %v", c.name, got, c.want)
		}
	}
	if !errors.Is(ErrAdminAppSignInRefused, ErrRoleNotFound) {
		t.Error("ErrAdminAppSignInRefused must wrap ErrRoleNotFound")
	}
}

func adminLogin(t *testing.T, role model.UserRole, policy AdminAppSignInPolicy) (*dto.LoginResponse, *adminAppAudit, error) {
	t.Helper()
	pw := "Str0ng!Passw0rd"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user := &model.User{ID: 9, Email: "root@example.com", HashedPassword: hash, IsVerified: true, Role: role}
	svc := newLoginSvc(t, user) // app client_id "admin-console-dev2", no membership
	audit := &adminAppAudit{}
	svc.auditRepo = audit
	svc.SetAdminAppSignInPolicy(policy)
	resp, err := svc.Login(context.Background(), dto.LoginRequest{
		Email: user.Email, Password: pw, AppClientID: "admin-console-dev2",
	})
	return resp, audit, err
}

func TestAdminAppSignIn_Login(t *testing.T) {
	for _, role := range []model.UserRole{model.UserRoleSuperadmin, model.UserRoleAdmin} {
		t.Run(string(role)+"/enforce refuses an app", func(t *testing.T) {
			_, audit, err := adminLogin(t, role, NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"admin-bff"}))
			if !errors.Is(err, ErrAdminAppSignInRefused) {
				t.Fatalf("Login = %v, want ErrAdminAppSignInRefused", err)
			}
			if len(audit.rows) != 1 || audit.rows[0].Success || audit.rows[0].Details["path"] != "login" {
				t.Errorf("audit rows = %+v, want one refused login", audit.rows)
			}
		})
		t.Run(string(role)+"/enforce allows a console", func(t *testing.T) {
			resp, audit, err := adminLogin(t, role, NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"admin-console-dev2"}))
			if err != nil || resp.AccessToken == "" {
				t.Fatalf("console login = %v", err)
			}
			if len(audit.rows) != 0 {
				t.Errorf("a console sign-in was audited: %+v", audit.rows)
			}
		})
		t.Run(string(role)+"/observe allows and audits", func(t *testing.T) {
			resp, audit, err := adminLogin(t, role, NewAdminAppSignInPolicy(AdminAppSignInObserve, []string{"admin-bff"}))
			if err != nil || resp.AccessToken == "" {
				t.Fatalf("observe login = %v", err)
			}
			if len(audit.rows) != 1 || !audit.rows[0].Success || audit.rows[0].Details["policy"] != AdminAppSignInObserve {
				t.Errorf("audit rows = %+v, want one allowed sign-in", audit.rows)
			}
		})
		t.Run(string(role)+"/off is unchanged", func(t *testing.T) {
			resp, audit, err := adminLogin(t, role, AdminAppSignInPolicy{})
			if err != nil || resp.Roles[0] != string(model.AppRoleAdmin) || len(audit.rows) != 0 {
				t.Fatalf("off: %v %+v %d rows", err, resp, len(audit.rows))
			}
		})
	}
}

// An ordinary user without membership keeps the generic refusal, not the
// admin one, under enforce.
func TestAdminAppSignIn_Login_OrdinaryUserUnaffected(t *testing.T) {
	_, audit, err := adminLogin(t, model.UserRoleUser, NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"admin-bff"}))
	if !errors.Is(err, ErrRoleNotFound) || errors.Is(err, ErrAdminAppSignInRefused) || len(audit.rows) != 0 {
		t.Fatalf("ordinary user: %v, %d rows", err, len(audit.rows))
	}
}

func TestAdminAppSignIn_Authorize(t *testing.T) {
	super := &model.User{ID: 9, Email: "root@example.com", IsVerified: true, Role: model.UserRoleSuperadmin}

	svc := newAuthorizeSvc(t, super) // app client_id "admin-console-dev2", no membership
	audit := &adminAppAudit{}
	svc.auditRepo = audit
	svc.SetAdminAppSignInPolicy(NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"admin-bff"}))
	if _, err := svc.Authorize(context.Background(), authorizeReq(), super.ID); !errors.Is(err, ErrAdminAppSignInRefused) {
		t.Fatalf("Authorize on an app = %v, want ErrAdminAppSignInRefused", err)
	}
	if len(audit.rows) != 1 || audit.rows[0].Details["path"] != "authorize" {
		t.Errorf("audit rows = %+v, want one refused authorize", audit.rows)
	}

	svc = newAuthorizeSvc(t, super)
	svc.SetAdminAppSignInPolicy(NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"admin-console-dev2"}))
	if code, err := svc.Authorize(context.Background(), authorizeReq(), super.ID); err != nil || code == "" {
		t.Fatalf("Authorize on a console = %q, %v", code, err)
	}
}

// Turning on enforce ends an admin's existing app session at its next refresh.
func TestAdminAppSignIn_Refresh(t *testing.T) {
	super := &model.User{ID: 9, Email: "root@example.com", IsVerified: true, Role: model.UserRoleSuperadmin}

	svc, _, rt := newRefreshNoMembershipSvc(t, super) // app client_id "admin-console"
	svc.SetAdminAppSignInPolicy(NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"admin-bff"}))
	_, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(rt), "admin-console", "")
	if !errors.Is(err, ErrAdminAppSignInRefused) || !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("refresh on an app = %v, want ErrAdminAppSignInRefused (an invalid_grant)", err)
	}

	svc, _, rt = newRefreshNoMembershipSvc(t, super)
	svc.SetAdminAppSignInPolicy(NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"admin-console"}))
	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(rt), "admin-console", ""); err != nil {
		t.Fatalf("refresh on a console = %v", err)
	}
}
