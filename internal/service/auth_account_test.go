// Package service — AuthenticateAccount backs the hosted account page
// (ACCOUNT_SECURITY_PAGE): it checks a user's own password, with Login's
// lockout and audit, and their second factor, without issuing a token or
// requiring an application membership. Socrate admins are refused.
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

func accountUser(t *testing.T, role model.UserRole, mfa bool) (*model.User, string) {
	t.Helper()
	pw := "Str0ng!Passw0rd"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return &model.User{ID: 7, Email: "op@example.com", HashedPassword: hash, IsVerified: true, Role: role, MFAEnabled: mfa}, pw
}

func TestAuthenticateAccount_UserWithoutMFA(t *testing.T) {
	user, pw := accountUser(t, model.UserRoleUser, false)
	svc := newLoginSvc(t, user) // no membership in any app: not needed here
	got, err := svc.AuthenticateAccount(context.Background(), user.Email, pw, "")
	if err != nil || got == nil || got.ID != user.ID {
		t.Fatalf("got %v, %v; want the user", got, err)
	}
}

func TestAuthenticateAccount_WrongPasswordOrUnknownEmail(t *testing.T) {
	user, _ := accountUser(t, model.UserRoleUser, false)
	svc := newLoginSvc(t, user)
	if _, err := svc.AuthenticateAccount(context.Background(), user.Email, "wrong", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.AuthenticateAccount(context.Background(), "nobody@example.com", "x", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown email = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthenticateAccount_SecondFactor(t *testing.T) {
	user, pw := accountUser(t, model.UserRoleUser, true)

	svc := newLoginSvc(t, user)
	svc.mfa = &stubMFAVerifier{}
	if _, err := svc.AuthenticateAccount(context.Background(), user.Email, pw, ""); !errors.Is(err, ErrMFARequired) {
		t.Errorf("no code = %v, want ErrMFARequired", err)
	}

	svc.mfa = &stubMFAVerifier{verifyErr: ErrMFAInvalidCode}
	if _, err := svc.AuthenticateAccount(context.Background(), user.Email, pw, "000000"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Errorf("wrong code = %v, want ErrMFAInvalidCode", err)
	}

	stub := &stubMFAVerifier{}
	svc.mfa = stub
	if got, err := svc.AuthenticateAccount(context.Background(), user.Email, pw, "123456"); err != nil || got == nil {
		t.Errorf("valid code = %v, %v; want the user", got, err)
	}
	if !stub.verifyHit {
		t.Error("the code was not verified")
	}
}

// Admins manage MFA in the admin console, under ADMIN_MFA_POLICY.
func TestAuthenticateAccount_RefusesSocrateAdmins(t *testing.T) {
	for _, role := range []model.UserRole{model.UserRoleAdmin, model.UserRoleSuperadmin} {
		user, pw := accountUser(t, role, false)
		if _, err := newLoginSvc(t, user).AuthenticateAccount(context.Background(), user.Email, pw, ""); !errors.Is(err, ErrAccountPageAdmin) {
			t.Errorf("%s = %v, want ErrAccountPageAdmin", role, err)
		}
	}
}

func TestAuthenticateAccount_RefusesUnverifiedAndLocked(t *testing.T) {
	user, pw := accountUser(t, model.UserRoleUser, false)
	user.IsVerified = false
	if _, err := newLoginSvc(t, user).AuthenticateAccount(context.Background(), user.Email, pw, ""); !errors.Is(err, ErrUserNotVerified) {
		t.Errorf("unverified = %v, want ErrUserNotVerified", err)
	}

	locked, pw := accountUser(t, model.UserRoleUser, false)
	until := time.Now().Add(time.Hour)
	locked.LockedUntil = &until
	if _, err := newLoginSvc(t, locked).AuthenticateAccount(context.Background(), locked.Email, pw, ""); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("locked = %v, want ErrAccountLocked", err)
	}
}
