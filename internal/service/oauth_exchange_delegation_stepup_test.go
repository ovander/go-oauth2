package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// mintTokenWithAmr mints an actor access token carrying the given amr methods.
func mintTokenWithAmr(t *testing.T, ts *auth.TokenService, userID uint, scope string, amr []string) string {
	t.Helper()
	acr := ""
	if amrContains(amr, "mfa") {
		acr = "mfa"
	}
	set, err := ts.GenerateTokenSetWithAuth(&model.User{ID: userID, TokenVersion: 1}, &model.App{ClientID: "actor-app"}, "user", scope, nil, "", 0, amr, acr)
	if err != nil {
		t.Fatalf("GenerateTokenSetWithAuth: %v", err)
	}
	return set.AccessToken
}

func delegationStepUpSvc(t *testing.T, mode string) (*oauthService, *captureAuditRepo, *auth.TokenService) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	svc.delegationStepUpMode = mode
	return svc, audit, ts
}

// Enforce denies a delegation whose actor did not authenticate with MFA.
func TestExchangeToken_DelegationStepUpEnforceDeniesNonMFAActor(t *testing.T) {
	svc, _, ts := delegationStepUpSvc(t, stepUpModeEnforce)

	subj := mintToken(t, ts, 100, "read write")
	actor := mintTokenWithAmr(t, ts, 200, "read", []string{"pwd"}) // no mfa
	form := exForm(subj, actor, "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrDelegationStepUpRequired) {
		t.Fatalf("want ErrDelegationStepUpRequired for a non-MFA actor, got %v", err)
	}
}

// Enforce allows a delegation whose actor authenticated with MFA.
func TestExchangeToken_DelegationStepUpEnforceAllowsMFAActor(t *testing.T) {
	svc, audit, ts := delegationStepUpSvc(t, stepUpModeEnforce)

	subj := mintToken(t, ts, 100, "read write")
	actor := mintTokenWithAmr(t, ts, 200, "read", []string{"pwd", "otp", "mfa"})
	form := exForm(subj, actor, "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("MFA actor should issue: %v", err)
	}
	if resp == nil || resp.AccessToken == "" {
		t.Fatal("expected an issued token for an MFA actor")
	}
	if audit.last.Details["delegation_stepup"] != "mfa" {
		t.Errorf("audit delegation_stepup = %v, want mfa", audit.last.Details["delegation_stepup"])
	}
}

// Observe records the would-be denial for a non-MFA actor but still issues.
func TestExchangeToken_DelegationStepUpObserveIssuesAndAudits(t *testing.T) {
	svc, audit, ts := delegationStepUpSvc(t, stepUpModeObserve)

	subj := mintToken(t, ts, 100, "read write")
	actor := mintTokenWithAmr(t, ts, 200, "read", []string{"pwd"})
	form := exForm(subj, actor, "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("observe must still issue: %v", err)
	}
	if resp == nil || resp.AccessToken == "" {
		t.Fatal("observe must issue a token")
	}
	if audit.last.Details["delegation_stepup"] != "would_deny" {
		t.Errorf("audit delegation_stepup = %v, want would_deny", audit.last.Details["delegation_stepup"])
	}
}

// Off skips the check entirely (a non-MFA actor still issues, no telemetry).
func TestExchangeToken_DelegationStepUpOffSkips(t *testing.T) {
	svc, audit, ts := delegationStepUpSvc(t, stepUpModeOff)

	subj := mintToken(t, ts, 100, "read write")
	actor := mintTokenWithAmr(t, ts, 200, "read", []string{"pwd"})
	form := exForm(subj, actor, "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); err != nil {
		t.Fatalf("off must not deny: %v", err)
	}
	if _, ok := audit.last.Details["delegation_stepup_mode"]; ok {
		t.Errorf("off must not record delegation step-up telemetry, got %v", audit.last.Details["delegation_stepup_mode"])
	}
}

// Impersonation (actor-absent) is unaffected by the delegation step-up check.
func TestExchangeToken_DelegationStepUpDoesNotApplyToImpersonation(t *testing.T) {
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	svc.delegationStepUpMode = stepUpModeEnforce

	form := exForm(mintToken(t, ts, 100, "read write"), "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); err != nil {
		t.Fatalf("impersonation must not be gated by delegation step-up: %v", err)
	}
}
