package service

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/tokenexchange"
)

func exchangeForm(delegation bool) url.Values {
	v := url.Values{}
	v.Set("grant_type", tokenexchange.GrantType)
	v.Set("subject_token", "subj-tok")
	v.Set("subject_token_type", tokenexchange.TokenTypeAccessToken)
	v.Set("audience", "https://api.example.com")
	if delegation {
		v.Set("actor_token", "act-tok")
		v.Set("actor_token_type", tokenexchange.TokenTypeJWT)
	}
	return v
}

func TestExchangeToken_OffIsUnsupportedAndNotAudited(t *testing.T) {
	audit := &captureAuditRepo{}
	svc := &oauthService{
		appRepo:           &crit02AppRepo{app: &model.App{ID: 1, ClientID: "c", AllowTokenExchange: true}},
		auditRepo:         audit,
		tokenExchangeMode: TokenExchangeModeOff,
	}

	if _, err := svc.ExchangeToken(context.Background(), exchangeForm(true), "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("off mode: want ErrInvalidGrantType, got %v", err)
	}
	if audit.last != nil {
		t.Fatal("off mode must not audit")
	}
}

func TestExchangeToken_ShadowAuditsDelegationAndDoesNotIssue(t *testing.T) {
	audit := &captureAuditRepo{}
	svc := &oauthService{
		appRepo:           &crit02AppRepo{app: &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: false}},
		auditRepo:         audit,
		tokenExchangeMode: TokenExchangeModeShadow,
	}

	resp, err := svc.ExchangeToken(context.Background(), exchangeForm(true), "c", "")
	if resp != nil {
		t.Fatal("shadow must not issue a token")
	}
	if !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("shadow must report unsupported, got %v", err)
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventTokenExchange {
		t.Fatalf("expected a token_exchange audit row, got %+v", audit.last)
	}
	d := audit.last.Details
	if d["outcome"] != "shadow_not_issued" {
		t.Fatalf("outcome = %v, want shadow_not_issued", d["outcome"])
	}
	if d["is_delegation"] != true {
		t.Fatalf("is_delegation = %v, want true", d["is_delegation"])
	}
	if d["allow_token_exchange"] != true {
		t.Fatalf("allow_token_exchange = %v, want true", d["allow_token_exchange"])
	}
}

func TestExchangeToken_ShadowAuditsImpersonationClassification(t *testing.T) {
	audit := &captureAuditRepo{}
	svc := &oauthService{
		appRepo:           &crit02AppRepo{app: &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true}},
		auditRepo:         audit,
		tokenExchangeMode: TokenExchangeModeShadow,
	}

	if _, err := svc.ExchangeToken(context.Background(), exchangeForm(false), "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("want ErrInvalidGrantType, got %v", err)
	}
	if audit.last == nil || audit.last.Details["is_delegation"] != false {
		t.Fatalf("expected is_delegation=false for impersonation, got %+v", audit.last)
	}
}

func TestExchangeToken_ShadowAuditsParseError(t *testing.T) {
	audit := &captureAuditRepo{}
	svc := &oauthService{
		appRepo:           &crit02AppRepo{app: &model.App{ID: 7, ClientID: "c"}},
		auditRepo:         audit,
		tokenExchangeMode: TokenExchangeModeShadow,
	}

	// Missing subject_token -> parse error.
	bad := url.Values{}
	bad.Set("grant_type", tokenexchange.GrantType)
	if _, err := svc.ExchangeToken(context.Background(), bad, "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("want ErrInvalidGrantType, got %v", err)
	}
	if audit.last == nil || audit.last.Details["outcome"] != "parse_error" {
		t.Fatalf("expected a parse_error audit row, got %+v", audit.last)
	}
}
