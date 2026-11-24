package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/internal/shared/auth/tokenexchange"
)

// Token exchange checks a presented subject or actor token against the
// server's state, as the refresh grant does with its token: not rotated or
// revoked, its DPoP key proven when it is sender-constrained, and its user
// still current (token version) and not locked.

// exchangeUsedTokens answers IsUsed from a set of jtis, or with err.
type exchangeUsedTokens struct {
	repository.UsedTokenRepository
	used map[string]bool
	err  error
}

func (r *exchangeUsedTokens) IsUsed(_ context.Context, jti string) (bool, error) {
	return r.used[jti], r.err
}

// jtiOf reads the jti of a token this test minted (signature already trusted).
func jtiOf(t *testing.T, tok string) string {
	t.Helper()
	var c jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tok, &c); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func newCheckedExchangeSvc(t *testing.T) (*oauthService, *captureAuditRepo, *auth.TokenService, *exchangeUserRepo, *exchangeUsedTokens) {
	t.Helper()
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	users := svc.userRepo.(*exchangeUserRepo)
	used := &exchangeUsedTokens{used: map[string]bool{}}
	svc.usedTokenRepo = used
	return svc, audit, ts, users, used
}

func expectExchangeDenied(t *testing.T, svc *oauthService, audit *captureAuditRepo, ctx context.Context, subject, actor, wantReason string) {
	t.Helper()
	_, err := svc.ExchangeToken(ctx, exForm(subject, actor, "read", "https://api"), "c", exchangeTestSecret)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("%s: %v, want ErrInvalidToken", wantReason, err)
	}
	if audit.last == nil {
		t.Fatalf("%s: no audit row", wantReason)
	}
	if audit.last.Details["deny_reason"] != wantReason {
		t.Fatalf("deny_reason %v, want %s", audit.last.Details["deny_reason"], wantReason)
	}
}

func TestExchangeToken_SubjectTokenChecks(t *testing.T) {
	ctx := context.Background()

	t.Run("valid", func(t *testing.T) {
		svc, _, ts, _, _ := newCheckedExchangeSvc(t)
		if _, err := svc.ExchangeToken(ctx, exForm(mintToken(t, ts, 100, "read"), "", "read", "https://api"), "c", exchangeTestSecret); err != nil {
			t.Fatalf("valid subject token: %v", err)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		svc, audit, ts, _, used := newCheckedExchangeSvc(t)
		tok := mintToken(t, ts, 100, "read")
		used.used[jtiOf(t, tok)] = true
		expectExchangeDenied(t, svc, audit, ctx, tok, "", "subject_revoked")
	})
	t.Run("revocation list unreadable", func(t *testing.T) {
		svc, audit, ts, _, used := newCheckedExchangeSvc(t)
		used.err = errors.New("db down")
		expectExchangeDenied(t, svc, audit, ctx, mintToken(t, ts, 100, "read"), "", "subject_revoked")
	})
	t.Run("token version", func(t *testing.T) {
		svc, audit, ts, users, _ := newCheckedExchangeSvc(t)
		users.users[100] = &model.User{ID: 100, TokenVersion: 2}
		expectExchangeDenied(t, svc, audit, ctx, mintToken(t, ts, 100, "read"), "", "subject_token_version")
	})
	t.Run("locked", func(t *testing.T) {
		svc, audit, ts, users, _ := newCheckedExchangeSvc(t)
		until := time.Now().Add(time.Hour)
		users.users[100] = &model.User{ID: 100, TokenVersion: 1, LockedUntil: &until}
		expectExchangeDenied(t, svc, audit, ctx, mintToken(t, ts, 100, "read"), "", "subject_locked")
	})
	t.Run("unknown user", func(t *testing.T) {
		svc, audit, ts, users, _ := newCheckedExchangeSvc(t)
		users.users[100] = nil
		expectExchangeDenied(t, svc, audit, ctx, mintToken(t, ts, 100, "read"), "", "subject_unknown_user")
	})
}

// A DPoP-bound subject token is exchanged only with a proof for its key.
func TestExchangeToken_DPoPBoundSubjectToken(t *testing.T) {
	svc, audit, ts, _, _ := newCheckedExchangeSvc(t)
	set, err := ts.GenerateTokenSetWithDPoP(&model.User{ID: 100, TokenVersion: 1}, &model.App{ClientID: "subject-app"}, "user", "read", nil, "", 0, "jkt-subject")
	if err != nil {
		t.Fatal(err)
	}
	expectExchangeDenied(t, svc, audit, context.Background(), set.AccessToken, "", "subject_dpop_mismatch")
	other := context.WithValue(context.Background(), contextkeys.DPoPJKTKey, "jkt-other")
	expectExchangeDenied(t, svc, audit, other, set.AccessToken, "", "subject_dpop_mismatch")

	same := context.WithValue(context.Background(), contextkeys.DPoPJKTKey, "jkt-subject")
	if _, err := svc.ExchangeToken(same, exForm(set.AccessToken, "", "read", "https://api"), "c", exchangeTestSecret); err != nil {
		t.Fatalf("with a proof for the subject token's key: %v", err)
	}
}

// A rotated refresh token cannot be exchanged.
func TestExchangeToken_RotatedRefreshSubjectToken(t *testing.T) {
	svc, audit, ts, _, used := newCheckedExchangeSvc(t)
	set, err := ts.GenerateTokenSet(&model.User{ID: 100, TokenVersion: 1}, &model.App{ClientID: "subject-app"}, "user", "read", nil, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	used.used[jtiOf(t, set.RefreshToken)] = true
	form := exForm(set.RefreshToken, "", "read", "https://api")
	form.Set("subject_token_type", tokenexchange.TokenTypeRefreshToken)
	if _, err := svc.ExchangeToken(context.Background(), form, "c", exchangeTestSecret); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("rotated refresh token: %v, want ErrInvalidToken", err)
	}
	if audit.last == nil {
		t.Fatal("no audit row")
	}
	if audit.last.Details["deny_reason"] != "subject_revoked" {
		t.Fatalf("deny_reason %v, want subject_revoked", audit.last.Details["deny_reason"])
	}
}

// The actor token of a delegation gets the same checks.
func TestExchangeToken_ActorTokenChecks(t *testing.T) {
	svc, audit, ts, users, used := newCheckedExchangeSvc(t)
	subject := mintToken(t, ts, 100, "read write")
	actor := mintToken(t, ts, 200, "read")
	used.used[jtiOf(t, actor)] = true
	expectExchangeDenied(t, svc, audit, context.Background(), subject, actor, "actor_revoked")

	delete(used.used, jtiOf(t, actor))
	until := time.Now().Add(time.Hour)
	users.users[200] = &model.User{ID: 200, TokenVersion: 1, LockedUntil: &until}
	expectExchangeDenied(t, svc, audit, context.Background(), subject, actor, "actor_locked")
}

// A service-account token (client_credentials, sub "app:<id>") has no user:
// it is exchangeable while its app exists and is active, for instance as the
// actor token of a delegation, and the revocation list still applies to it.
func TestExchangeToken_ServiceAccountToken(t *testing.T) {
	svc, audit, ts, _, used := newCheckedExchangeSvc(t)
	app, err := svc.appRepo.FindByClientID(context.Background(), "c")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ts.GenerateClientCredentialsToken(app, "read")
	if err != nil {
		t.Fatal(err)
	}
	subject := mintToken(t, ts, 100, "read write")
	if _, err := svc.ExchangeToken(context.Background(), exForm(subject, actor, "read", "https://api"), "c", exchangeTestSecret); err != nil {
		t.Fatalf("delegation with the client's own service-account token as actor: %v", err)
	}

	used.used[jtiOf(t, actor)] = true
	expectExchangeDenied(t, svc, audit, context.Background(), subject, actor, "actor_revoked")
	delete(used.used, jtiOf(t, actor))

	app.Active = false
	// The requesting client is the same app here, so deactivating it is
	// refused earlier, at client authentication; check the token on its own.
	if reason := svc.checkExchangeToken(context.Background(), exchangeToken{sub: "app:7", versioned: true}); reason != "inactive_app" {
		t.Fatalf("inactive app: %q, want inactive_app", reason)
	}
	app.Active = true
	if reason := svc.checkExchangeToken(context.Background(), exchangeToken{sub: "app:999", versioned: true}); reason != "unknown_app" {
		t.Fatalf("unknown app: %q, want unknown_app", reason)
	}
	if reason := svc.checkExchangeToken(context.Background(), exchangeToken{sub: "app:x", versioned: true}); reason != "unknown_app" {
		t.Fatalf("malformed app id: %q, want unknown_app", reason)
	}
}

// An ID token cannot be revoked (it carries no token version), so it is not
// accepted as a subject token.
func TestExchangeToken_IDTokenSubjectRefused(t *testing.T) {
	svc, audit, ts, _, _ := newCheckedExchangeSvc(t)
	set, err := ts.GenerateTokenSet(&model.User{ID: 100, TokenVersion: 1}, &model.App{ClientID: "subject-app"}, "user", "openid read", nil, "n", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if set.IDToken == "" {
		t.Fatal("no ID token minted")
	}
	form := exForm(set.IDToken, "", "read", "https://api")
	form.Set("subject_token_type", tokenexchange.TokenTypeIDToken)
	if _, err := svc.ExchangeToken(context.Background(), form, "c", exchangeTestSecret); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ID token as subject: %v, want ErrInvalidToken", err)
	}
	if audit.last == nil {
		t.Fatal("no audit row")
	}
	if audit.last.Details["deny_reason"] != "subject_id_token" {
		t.Fatalf("deny_reason %v, want subject_id_token", audit.last.Details["deny_reason"])
	}
}
