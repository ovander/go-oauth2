// Package service — tests for L2 (introspection audience binding) and L3
// (revoke ownership check), Socrate suite audit remediation.
//
// L2 fix: Introspect() now takes the authenticated caller's own client_id
// (requestingClientID). RFC 7662 permits any authenticated client to
// introspect any token, but doing so unconditionally lets one client learn
// another client's sub/username/scope/aud — an information-disclosure
// vector. RFC 7662 §2.2 notes a resource server MAY restrict which clients
// may introspect a given token; when requestingClientID does not appear in
// the token's own audience, Introspect now reports active:false instead of
// returning the full claim set.
//
// L3 fix: Revoke() now takes the authenticated caller's own client_id on the
// client-credential path (requestingClientID). Without this check, any
// authenticated client presenting a token value it does not own (e.g. one it
// observed or was handed) could blacklist that token's JTI — a targeted DoS
// against another party's session. When requestingClientID does not appear
// in the presented token's audience, the call still returns nil (RFC 7009
// §2.2 — the client-visible behaviour is always 200 OK) but the token is
// left un-revoked.
package service

import (
	"context"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// ---------------------------------------------------------------------------
// L2: Introspect audience binding
// ---------------------------------------------------------------------------

func TestL2_Introspect_SameClient_ReturnsActiveWithClaims(t *testing.T) {
	user := &model.User{ID: 50, Email: "owner@example.com", TokenVersion: 1}
	app := &model.App{ID: 1, ClientID: "my-app"}
	usedRepo := newMemUsedTokenRepo()
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken, "my-app")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Fatal("L2: same-client introspection must return active:true")
	}
	if resp.Username != user.Email {
		t.Errorf("L2: expected full claims (username=%q) for same-client introspection, got %q", user.Email, resp.Username)
	}
}

func TestL2_Introspect_CrossClient_ReturnsInactive(t *testing.T) {
	user := &model.User{ID: 51, Email: "owner2@example.com", TokenVersion: 1}
	app := &model.App{ID: 2, ClientID: "my-app"}
	usedRepo := newMemUsedTokenRepo()
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	// A different, unrelated client authenticates and tries to introspect
	// "my-app"'s token.
	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken, "other-client")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if resp.Active {
		t.Error("L2: cross-client introspection must return active:false, not the token's full claim set")
	}
	if resp.Username != "" || resp.Sub != "" || resp.Scope != "" {
		t.Errorf("L2: cross-client introspection must not leak claims, got %+v", resp)
	}
}

func TestL2_Introspect_EmptyRequestingClientID_StillActive(t *testing.T) {
	// requestingClientID is only empty when the caller could not identify a
	// client (should not happen once the handler enforces client auth); the
	// audience gate must not apply in that case, preserving prior behaviour.
	user := &model.User{ID: 52, Email: "owner3@example.com", TokenVersion: 1}
	app := &model.App{ID: 3, ClientID: "my-app"}
	usedRepo := newMemUsedTokenRepo()
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken, "")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Error("L2: an empty requestingClientID must not trigger the audience gate")
	}
}

// ---------------------------------------------------------------------------
// L3: Revoke ownership check
// ---------------------------------------------------------------------------

func TestL3_Revoke_SameClient_BlacklistsJTI(t *testing.T) {
	user := &model.User{ID: 60, Email: "revoker@example.com", TokenVersion: 1}
	app := &model.App{ID: 4, ClientID: "my-app"}
	usedRepo := newMemUsedTokenRepo()
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, err := ts.VerifyAccessToken(tokenSet.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	// "my-app" authenticates and revokes its own token (userID=0: no user
	// context on the client-credential path).
	if err := svc.Revoke(context.Background(), tokenSet.AccessToken, 0, "my-app"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	used, _ := usedRepo.IsUsed(context.Background(), claims.ID)
	if !used {
		t.Error("L3: same-client revoke must blacklist the token's JTI")
	}
}

func TestL3_Revoke_CrossClient_DoesNotBlacklistJTI(t *testing.T) {
	user := &model.User{ID: 61, Email: "victim@example.com", TokenVersion: 1}
	app := &model.App{ID: 5, ClientID: "my-app"}
	usedRepo := newMemUsedTokenRepo()
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, err := ts.VerifyAccessToken(tokenSet.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	// A different, unrelated client obtains the token value and tries to
	// revoke it. The call must still behave as success (nil error — the
	// handler always responds 200 per RFC 7009 §2.2), but the token must not
	// actually be revoked.
	if err := svc.Revoke(context.Background(), tokenSet.AccessToken, 0, "other-client"); err != nil {
		t.Fatalf("Revoke returned an error (RFC 7009 requires it to behave as success): %v", err)
	}

	used, _ := usedRepo.IsUsed(context.Background(), claims.ID)
	if used {
		t.Error("L3: cross-client revoke must NOT blacklist a token it does not own")
	}

	// The token must still introspect as active — proof it was not revoked.
	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken, "my-app")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Error("L3: token must still be active after a denied cross-client revoke attempt")
	}
}

func TestL3_Revoke_SameClient_RefreshToken_BlacklistsJTI(t *testing.T) {
	user := &model.User{ID: 62, Email: "revoker2@example.com", TokenVersion: 1}
	app := &model.App{ID: 6, ClientID: "my-app"}
	usedRepo := newMemUsedTokenRepo()
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid offline_access", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	rClaims, err := ts.VerifyRefreshToken(tokenSet.RefreshToken)
	if err != nil {
		t.Fatalf("VerifyRefreshToken: %v", err)
	}

	if err := svc.Revoke(context.Background(), tokenSet.RefreshToken, 0, "my-app"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	used, _ := usedRepo.IsUsed(context.Background(), rClaims.ID)
	if !used {
		t.Error("L3: same-client refresh-token revoke must blacklist the JTI")
	}
}

func TestL3_Revoke_CrossClient_RefreshToken_DoesNotBlacklistJTI(t *testing.T) {
	user := &model.User{ID: 63, Email: "victim2@example.com", TokenVersion: 1}
	app := &model.App{ID: 7, ClientID: "my-app"}
	usedRepo := newMemUsedTokenRepo()
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid offline_access", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	rClaims, err := ts.VerifyRefreshToken(tokenSet.RefreshToken)
	if err != nil {
		t.Fatalf("VerifyRefreshToken: %v", err)
	}

	if err := svc.Revoke(context.Background(), tokenSet.RefreshToken, 0, "other-client"); err != nil {
		t.Fatalf("Revoke returned an error: %v", err)
	}

	used, _ := usedRepo.IsUsed(context.Background(), rClaims.ID)
	if used {
		t.Error("L3: cross-client revoke must NOT blacklist a refresh token it does not own")
	}
}

func TestL3_Revoke_UserBearerPath_Unaffected(t *testing.T) {
	// The user-Bearer self-revocation path (requestingClientID == "") must
	// keep its existing behaviour — the L3 ownership check only gates the
	// client-credential path.
	user := &model.User{ID: 64, Email: "self-revoker@example.com", TokenVersion: 1}
	app := &model.App{ID: 8, ClientID: "my-app"}
	usedRepo := newMemUsedTokenRepo()
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, err := ts.VerifyAccessToken(tokenSet.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	if err := svc.Revoke(context.Background(), tokenSet.AccessToken, user.ID, ""); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	used, _ := usedRepo.IsUsed(context.Background(), claims.ID)
	if !used {
		t.Error("L3: user-Bearer self-revocation path must be unaffected by the ownership check")
	}
}
