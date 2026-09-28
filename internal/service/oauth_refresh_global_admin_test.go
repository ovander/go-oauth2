// Package service — the refresh grant follows the same global-admin rule as
// code issuance and hosted login: a global admin needs no per-app membership
// row. Before this, a superadmin could sign in to the admin console (which
// has no seeded membership) but its first refresh failed, so every console
// session died with its first access token.
package service

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// newRefreshNoMembershipSvc wires a refresh grant for user on a public client
// with NO membership row, and returns the service plus a refresh token.
func newRefreshNoMembershipSvc(t *testing.T, user *model.User) (*oauthService, *auth.TokenService, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "refresh-admin-keys-*")
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
	app := &model.App{ID: 1, ClientID: "admin-console", Active: true, IsPublic: true}
	codeRepo := newMemCodeRepo()
	cs := auth.NewCodeStoreWithTTL(codeRepo, 10*time.Minute)
	t.Cleanup(cs.Stop)

	svc := &oauthService{
		userRepo:        &high04UserRepo{user: user},
		appRepo:         &crit02AppRepo{app: app},
		userAppRoleRepo: &high04RoleRepo{role: nil}, // no membership for this user/app
		codeStore:       cs,
		tokenService:    ts,
		keyManager:      km,
		usedTokenRepo:   newMemUsedTokenRepo(),
		issuer:          "https://auth.example.com",
	}
	set, err := ts.GenerateTokenSet(user, app, string(model.AppRoleAdmin), "openid offline_access", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	return svc, ts, set.RefreshToken
}

func TestRefresh_GlobalAdmin_WithoutMembership_Succeeds(t *testing.T) {
	for _, role := range []model.UserRole{model.UserRoleSuperadmin, model.UserRoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			admin := &model.User{ID: 42, Email: "admin@example.com", IsVerified: true, Role: role}
			svc, ts, rt := newRefreshNoMembershipSvc(t, admin)

			resp, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(rt), "admin-console", "")
			if err != nil {
				t.Fatalf("refresh for a %s without membership: %v", role, err)
			}
			claims, err := ts.VerifyAccessToken(resp.AccessToken)
			if err != nil {
				t.Fatalf("VerifyAccessToken: %v", err)
			}
			if claims.Role != string(model.AppRoleAdmin) {
				t.Errorf("role claim = %q, want %q (implicit app admin)", claims.Role, model.AppRoleAdmin)
			}
		})
	}
}

func TestRefresh_NonAdmin_WithoutMembership_IsRoleNotFound(t *testing.T) {
	user := &model.User{ID: 7, Email: "user@example.com", IsVerified: true, Role: model.UserRoleUser}
	svc, _, rt := newRefreshNoMembershipSvc(t, user)

	_, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(rt), "admin-console", "")
	if !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("refresh for a non-admin without membership = %v, want ErrRoleNotFound", err)
	}
}

func TestRevokedTokenOwner(t *testing.T) {
	cases := []struct {
		name    string
		userID  uint
		subject string
		want    uint // 0 means nil
	}{
		{"caller known", 5, "9", 5},
		{"from numeric subject", 0, "9", 9},
		{"service token subject", 0, "app:3", 0},
		{"empty subject", 0, "", 0},
		{"zero subject", 0, "0", 0},
	}
	for _, c := range cases {
		got := revokedTokenOwner(c.userID, c.subject)
		switch {
		case c.want == 0 && got != nil:
			t.Errorf("%s: got %d, want nil", c.name, *got)
		case c.want != 0 && (got == nil || *got != c.want):
			t.Errorf("%s: got %v, want %d", c.name, got, c.want)
		}
	}
}
