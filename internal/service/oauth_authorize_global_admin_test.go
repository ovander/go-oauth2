// Package service — tests for the global-admin authorization-code bypass.
//
// Companion to the hosted-login bypass (auth_service.Login): a global
// admin/superadmin may also have an authorization code issued for any app
// without an explicit per-app membership row. This mirrors the login path and
// middleware.RequireAppAdmin, and is what lets a platform superadmin complete
// the first-party PKCE admin console flow (which has no seeded user_app_roles
// entry). Non-admins without a membership row are still rejected.
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

// newAuthorizeSvc builds an oauthService whose user/app/role triple satisfies a
// full authorization-code issuance for the given user, with NO per-app
// membership row (high04RoleRepo{role: nil}). The app is a public PKCE client,
// matching the admin console.
func newAuthorizeSvc(t *testing.T, user *model.User) *oauthService {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "authorize-keys-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	km, err := auth.NewKeyManager(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "https://auth.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		EmailTokenTTL:   24 * time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  24 * time.Hour,
	})

	app := &model.App{
		ID:           1,
		ClientID:     "admin-console-dev2",
		Active:       true,
		IsPublic:     true,
		RedirectURIs: model.StringArray{"http://localhost:5173/auth/callback"},
	}

	codeRepo := newMemCodeRepo()
	cs := auth.NewCodeStoreWithTTL(codeRepo, 10*time.Minute)
	t.Cleanup(cs.Stop)

	return &oauthService{
		userRepo:        &high04UserRepo{user: user},
		appRepo:         &crit02AppRepo{app: app},
		userAppRoleRepo: &high04RoleRepo{role: nil}, // no membership for this user/app
		codeStore:       cs,
		tokenService:    ts,
		keyManager:      km,
		issuer:          "https://auth.example.com",
	}
}

func authorizeReq() dto.AuthorizeRequest {
	return dto.AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "admin-console-dev2",
		RedirectURI:         "http://localhost:5173/auth/callback",
		Scope:               "openid",
		State:               "xyz",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		MaxAge:              -1,
	}
}

func TestAuthorize_GlobalAdmin_BypassesAppMembership(t *testing.T) {
	admin := &model.User{ID: 42, Email: "admin@example.com", IsVerified: true, Role: model.UserRoleSuperadmin}

	code, err := newAuthorizeSvc(t, admin).Authorize(context.Background(), authorizeReq(), admin.ID)
	if err != nil {
		t.Fatalf("a global admin should get an authorization code without per-app membership, got: %v", err)
	}
	if code == "" {
		t.Error("expected a non-empty authorization code")
	}
}

func TestAuthorize_NonAdmin_NoMembership_Rejected(t *testing.T) {
	user := &model.User{ID: 7, Email: "bob@example.com", IsVerified: true, Role: model.UserRoleUser}

	_, err := newAuthorizeSvc(t, user).Authorize(context.Background(), authorizeReq(), user.ID)
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("a non-admin without membership must be rejected with ErrRoleNotFound, got: %v", err)
	}
}
