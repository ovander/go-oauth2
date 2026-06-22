package service

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/tokenexchange"
)

// newShadowExchangeSvc builds an oauthService in shadow mode with a real token
// service (so presented tokens actually verify), the given requesting app, and a
// capturing audit repo.
func newShadowExchangeSvc(t *testing.T, app *model.App) (*oauthService, *captureAuditRepo, *auth.TokenService) {
	t.Helper()
	tmp, err := os.MkdirTemp("", "tx-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })

	km, err := auth.NewKeyManager(tmp)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "https://auth.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	})
	audit := &captureAuditRepo{}
	svc := &oauthService{
		appRepo:           &crit02AppRepo{app: app},
		auditRepo:         audit,
		tokenService:      ts,
		keyManager:        km,
		issuer:            "https://auth.example.com",
		tokenExchangeMode: TokenExchangeModeShadow,
	}
	return svc, audit, ts
}

func mintToken(t *testing.T, ts *auth.TokenService, userID uint, scope string) string {
	t.Helper()
	set, err := ts.GenerateTokenSet(&model.User{ID: userID, TokenVersion: 1}, &model.App{ClientID: "subject-app"}, "user", scope, nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	return set.AccessToken
}

func exForm(subjectTok, actorTok, reqScope, aud string) url.Values {
	v := url.Values{}
	v.Set("grant_type", tokenexchange.GrantType)
	v.Set("subject_token", subjectTok)
	v.Set("subject_token_type", tokenexchange.TokenTypeAccessToken)
	if reqScope != "" {
		v.Set("scope", reqScope)
	}
	if aud != "" {
		v.Set("audience", aud)
	}
	if actorTok != "" {
		v.Set("actor_token", actorTok)
		v.Set("actor_token_type", tokenexchange.TokenTypeAccessToken)
	}
	return v
}

func TestExchangeToken_OffIsUnsupportedAndNotAudited(t *testing.T) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 1, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeOff

	form := exForm(mintToken(t, ts, 100, "read write"), "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("off mode: want ErrInvalidGrantType, got %v", err)
	}
	if audit.last != nil {
		t.Fatal("off mode must not audit")
	}
}

func TestExchangeToken_ShadowDelegationAllow(t *testing.T) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})

	subj := mintToken(t, ts, 100, "read write")
	actor := mintToken(t, ts, 200, "read")
	form := exForm(subj, actor, "read", "https://api.example.com")

	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("shadow must report unsupported, got %v", err)
	}
	d := audit.last.Details
	if d["outcome"] != "shadow_allow" {
		t.Fatalf("outcome = %v, want shadow_allow", d["outcome"])
	}
	if d["is_delegation"] != true {
		t.Fatalf("is_delegation = %v, want true", d["is_delegation"])
	}
	if d["granted_scope"] != "read" {
		t.Fatalf("granted_scope = %v, want read", d["granted_scope"])
	}
	if d["subject_sub"] != "100" || d["actor_sub"] != "200" {
		t.Fatalf("subject/actor sub = %v/%v, want 100/200", d["subject_sub"], d["actor_sub"])
	}
}

func TestExchangeToken_ShadowImpersonationDeniedWithoutFlag(t *testing.T) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: false})

	form := exForm(mintToken(t, ts, 100, "read write"), "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("want ErrInvalidGrantType, got %v", err)
	}
	d := audit.last.Details
	if d["outcome"] != "denied" {
		t.Fatalf("outcome = %v, want denied", d["outcome"])
	}
	if d["deny_reason"] != ErrImpersonationNotAllowed.Error() {
		t.Fatalf("deny_reason = %v, want %q", d["deny_reason"], ErrImpersonationNotAllowed.Error())
	}
}

func TestExchangeToken_ShadowDeniedScopeEscalation(t *testing.T) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})

	// subject has "read"; request "admin" -> escalation denied.
	form := exForm(mintToken(t, ts, 100, "read"), mintToken(t, ts, 200, "read"), "admin", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("want ErrInvalidGrantType, got %v", err)
	}
	if audit.last.Details["deny_reason"] != ErrScopeNotSubset.Error() {
		t.Fatalf("deny_reason = %v, want scope-not-subset", audit.last.Details["deny_reason"])
	}
}

func TestExchangeToken_ShadowInvalidSubjectToken(t *testing.T) {
	svc, audit, _ := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})

	form := exForm("not-a-jwt", "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("want ErrInvalidGrantType, got %v", err)
	}
	if audit.last.Details["outcome"] != "invalid_subject_token" {
		t.Fatalf("outcome = %v, want invalid_subject_token", audit.last.Details["outcome"])
	}
}

func TestExchangeToken_ShadowParseError(t *testing.T) {
	svc, audit, _ := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c"})

	bad := url.Values{}
	bad.Set("grant_type", tokenexchange.GrantType) // missing subject_token
	if _, err := svc.ExchangeToken(context.Background(), bad, "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("want ErrInvalidGrantType, got %v", err)
	}
	if audit.last.Details["outcome"] != "parse_error" {
		t.Fatalf("outcome = %v, want parse_error", audit.last.Details["outcome"])
	}
}
