// HIGH-04: the consoles sign in through the hosted login (authService.Login),
// not AdminLogin, so ADMIN_MFA_POLICY must apply there to every Socrate admin.
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

func TestLogin_AdminMFAPolicy(t *testing.T) {
	pw := "Str0ng!Passw0rd"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	login := func(role model.UserRole, policy string) error {
		u := &model.User{ID: 42, Email: "someone@example.com", HashedPassword: hash, IsVerified: true, Role: role}
		svc := newLoginSvc(t, u)
		svc.adminMFAPolicy = policy
		svc.userAppRoleRepo = &high04RoleRepo{role: &model.UserAppRole{UserID: 42, AppID: 1, Role: model.AppRoleUser}}
		_, err := svc.Login(context.Background(), dto.LoginRequest{
			Email: "someone@example.com", Password: pw, AppClientID: "admin-console-dev2",
		})
		return err
	}
	for _, role := range []model.UserRole{model.UserRoleSuperadmin, model.UserRoleAdmin} {
		if err := login(role, MFAPolicyEnforce); !errors.Is(err, ErrMFAEnrollmentRequired) {
			t.Errorf("%s without MFA, enforce: err = %v, want ErrMFAEnrollmentRequired", role, err)
		}
		for _, policy := range []string{MFAPolicyOff, MFAPolicyObserve, ""} {
			if err := login(role, policy); err != nil {
				t.Errorf("%s without MFA, policy %q: err = %v, want sign-in", role, policy, err)
			}
		}
	}
	// The policy concerns Socrate admins only: an app user is not affected.
	if err := login(model.UserRoleUser, MFAPolicyEnforce); err != nil {
		t.Errorf("app user, enforce: err = %v, want sign-in", err)
	}
}
