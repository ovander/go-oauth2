// Package service — the authorization-code grant reports the sign-in behind the
// code: auth_time is when the user authenticated (not when the code was
// redeemed), and amr/acr say how. Refreshes keep both. Without them, a
// require_mfa obligation could never be met on an app's tokens, and a
// require_fresh_auth one was met by any code redemption.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

const authnVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func authnAuthorizeReq() dto.AuthorizeRequest {
	req := authorizeReq()
	sum := sha256.Sum256([]byte(authnVerifier))
	req.CodeChallenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return req
}

// redeem runs authorize (with ev on the context) then the code grant, and
// returns the service, the token service and the token response.
func redeem(t *testing.T, user *model.User, ev *auth.AuthnEvidence) (*oauthService, *dto.TokenResponse) {
	t.Helper()
	svc := newAuthorizeSvc(t, user)
	ctx := context.Background()
	if ev != nil {
		ctx = WithAuthnEvidence(ctx, *ev)
	}
	code, err := svc.Authorize(ctx, authnAuthorizeReq(), user.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	resp, err := svc.handleAuthorizationCodeGrant(context.Background(), dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  authorizeReq().RedirectURI,
		CodeVerifier: authnVerifier,
	}, "admin-console-dev2", "")
	if err != nil {
		t.Fatalf("code grant: %v", err)
	}
	return svc, resp
}

func accessClaims(t *testing.T, svc *oauthService, token string) *auth.AccessTokenClaims {
	t.Helper()
	c, err := svc.tokenService.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	return c
}

func TestCodeGrant_CarriesTheSignInEvidence(t *testing.T) {
	user := &model.User{ID: 42, Email: "op@example.test", IsVerified: true, Role: model.UserRoleSuperadmin}
	signedIn := time.Now().Add(-10 * time.Minute).Unix()
	ev := auth.AuthnEvidence{AuthTime: signedIn, AMR: []string{"pwd", "otp", "mfa"}, ACR: "mfa"}

	svc, resp := redeem(t, user, &ev)
	c := accessClaims(t, svc, resp.AccessToken)
	if c.AuthTime != signedIn {
		t.Errorf("auth_time = %d, want the sign-in time %d (not the redemption time)", c.AuthTime, signedIn)
	}
	if !reflect.DeepEqual(c.Amr, ev.AMR) || c.Acr != "mfa" {
		t.Errorf("amr/acr = %v/%q, want %v/mfa", c.Amr, c.Acr, ev.AMR)
	}

	// A refresh keeps the original sign-in: same auth_time, same amr/acr.
	refreshed, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(resp.RefreshToken), "admin-console-dev2", "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	rc := accessClaims(t, svc, refreshed.AccessToken)
	if rc.AuthTime != signedIn || !reflect.DeepEqual(rc.Amr, ev.AMR) || rc.Acr != "mfa" {
		t.Errorf("after refresh: auth_time=%d amr=%v acr=%q, want %d %v mfa", rc.AuthTime, rc.Amr, rc.Acr, signedIn, ev.AMR)
	}
}

// Without evidence (a caller predating it), the code records the user's last
// login, the best known sign-in, never a fresher one.
func TestCodeGrant_WithoutEvidenceUsesTheLastLogin(t *testing.T) {
	last := time.Now().Add(-20 * time.Minute).Truncate(time.Second)
	user := &model.User{ID: 42, Email: "op@example.test", IsVerified: true, Role: model.UserRoleSuperadmin, LastLogin: &last}
	svc, resp := redeem(t, user, nil)
	if c := accessClaims(t, svc, resp.AccessToken); c.AuthTime != last.Unix() || len(c.Amr) != 0 {
		t.Errorf("auth_time=%d amr=%v, want the last login %d and no amr", c.AuthTime, c.Amr, last.Unix())
	}

	// No evidence and no recorded login: redemption time, as before.
	fresh := &model.User{ID: 43, Email: "new@example.test", IsVerified: true, Role: model.UserRoleSuperadmin}
	before := time.Now().Unix()
	svc, resp = redeem(t, fresh, nil)
	if c := accessClaims(t, svc, resp.AccessToken); c.AuthTime < before {
		t.Errorf("auth_time=%d, want now (>= %d)", c.AuthTime, before)
	}
}

// max_age is checked against the sign-in this request rests on, which wins over
// LastLogin (moved by any later login, on any client).
func TestAuthorize_MaxAgeUsesTheSignInEvidence(t *testing.T) {
	now := time.Now()
	recent := now.Add(-5 * time.Second)
	user := &model.User{ID: 42, Email: "op@example.test", IsVerified: true, Role: model.UserRoleSuperadmin, LastLogin: &recent}
	req := authnAuthorizeReq()
	req.MaxAge = 60

	old := WithAuthnEvidence(context.Background(), auth.AuthnEvidence{AuthTime: now.Add(-time.Hour).Unix()})
	if _, err := newAuthorizeSvc(t, user).Authorize(old, req, user.ID); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("an hour-old sign-in with max_age=60 = %v, want ErrReauthRequired", err)
	}

	longAgo := now.Add(-time.Hour)
	user.LastLogin = &longAgo
	fresh := WithAuthnEvidence(context.Background(), auth.AuthnEvidence{AuthTime: now.Unix()})
	if _, err := newAuthorizeSvc(t, user).Authorize(fresh, req, user.ID); err != nil {
		t.Errorf("a fresh sign-in with an old LastLogin = %v, want a code", err)
	}
}
