// Package service — tests for the global-admin hosted-login bypass (issue #191).
// A global admin/superadmin may complete authService.Login for any app without
// an explicit per-app membership row (consistent with middleware.RequireAppAdmin),
// which is what lets a platform superadmin use the first-party PKCE admin console.
package service

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// loginUserRepo serves a single user by email (high04UserRepo only does FindByID).
type loginUserRepo struct {
	*high04UserRepo
}

func (r *loginUserRepo) FindByEmail(_ context.Context, email string) (*model.User, error) {
	if r.user != nil && r.user.Email == email {
		return r.user, nil
	}
	return nil, errors.New("not found")
}

func newLoginSvc(t *testing.T, user *model.User) *authService {
	t.Helper()
	tmp, err := os.MkdirTemp("", "login-keys-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	km, err := auth.NewKeyManager(tmp)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "https://auth.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		EmailTokenTTL:   time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  time.Hour,
	})
	return &authService{
		userRepo:          &loginUserRepo{&high04UserRepo{user: user}},
		appRepo:           &crit02AppRepo{app: &model.App{ID: 1, ClientID: "admin-console-dev2", Active: true}},
		userAppRoleRepo:   &high04RoleRepo{role: nil}, // no membership for this user/app
		tokenService:      ts,
		maxFailedAttempts: 5,
		lockoutDuration:   15 * time.Minute,
	}
}

func TestLogin_GlobalAdmin_BypassesAppMembership(t *testing.T) {
	pw := "Str0ng!Passw0rd"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	admin := &model.User{ID: 42, Email: "admin@example.com", HashedPassword: hash, IsVerified: true, Role: model.UserRoleSuperadmin}

	resp, err := newLoginSvc(t, admin).Login(context.Background(), dto.LoginRequest{
		Email: "admin@example.com", Password: pw, AppClientID: "admin-console-dev2",
	})
	if err != nil {
		t.Fatalf("a global admin should log in without per-app membership, got: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected an access token")
	}
	if len(resp.Roles) == 0 || resp.Roles[0] != string(model.AppRoleAdmin) {
		t.Errorf("expected an effective admin app role, got %v", resp.Roles)
	}
}

func TestLogin_NonAdmin_NoMembership_Rejected(t *testing.T) {
	pw := "Str0ng!Passw0rd"
	hash, _ := auth.HashPassword(pw)
	user := &model.User{ID: 7, Email: "bob@example.com", HashedPassword: hash, IsVerified: true, Role: model.UserRoleUser}

	_, err := newLoginSvc(t, user).Login(context.Background(), dto.LoginRequest{
		Email: "bob@example.com", Password: pw, AppClientID: "admin-console-dev2",
	})
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("a non-admin without membership must be rejected with ErrRoleNotFound, got: %v", err)
	}
}

// Login reports the sign-in it performed (when, and how), which the hosted
// login carries into the authorization code.
func TestLogin_ReturnsTheSignInEvidence(t *testing.T) {
	pw := "Str0ng!Passw0rd"
	hash, _ := auth.HashPassword(pw)
	admin := &model.User{ID: 42, Email: "admin@example.com", HashedPassword: hash, IsVerified: true, Role: model.UserRoleSuperadmin}
	before := time.Now().Unix()
	resp, err := newLoginSvc(t, admin).Login(context.Background(), dto.LoginRequest{
		Email: "admin@example.com", Password: pw, AppClientID: "admin-console-dev2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AuthTime < before || len(resp.AMR) != 1 || resp.AMR[0] != "pwd" || resp.ACR != "pwd" {
		t.Fatalf("evidence = %d %v %q, want now, [pwd], pwd", resp.AuthTime, resp.AMR, resp.ACR)
	}
}
