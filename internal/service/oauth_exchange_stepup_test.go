package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// mintTokenAt mints a subject access token whose auth_time is `age` in the past,
// so the step-up freshness check can be exercised deterministically.
func mintTokenAt(t *testing.T, ts *auth.TokenService, userID uint, scope string, age time.Duration) string {
	t.Helper()
	authTime := time.Now().Add(-age).Unix()
	set, err := ts.GenerateTokenSet(&model.User{ID: userID, TokenVersion: 1}, &model.App{ClientID: "subject-app"}, "user", scope, nil, "", authTime)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	return set.AccessToken
}

func stepUpImpSvc(t *testing.T, mode string, maxAge time.Duration) (*oauthService, *captureAuditRepo, *auth.TokenService) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	svc.impersonationStepUpMode = mode
	svc.impersonationMaxAuthAge = maxAge
	return svc, audit, ts
}

// Enforce denies impersonation when the subject's authentication is too old.
func TestExchangeToken_StepUpEnforceDeniesStaleSubject(t *testing.T) {
	svc, _, ts := stepUpImpSvc(t, stepUpModeEnforce, 15*time.Minute)

	form := exForm(mintTokenAt(t, ts, 100, "read write", time.Hour), "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("want ErrStepUpRequired for a stale subject, got %v", err)
	}
}

// Enforce allows impersonation when the subject authenticated recently.
func TestExchangeToken_StepUpEnforceAllowsFreshSubject(t *testing.T) {
	svc, audit, ts := stepUpImpSvc(t, stepUpModeEnforce, 15*time.Minute)

	form := exForm(mintTokenAt(t, ts, 100, "read write", time.Minute), "", "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("fresh subject should issue: %v", err)
	}
	if resp == nil || resp.AccessToken == "" {
		t.Fatal("expected an issued token for a fresh subject")
	}
	if audit.last.Details["stepup"] != "fresh" {
		t.Errorf("audit stepup = %v, want fresh", audit.last.Details["stepup"])
	}
}

// A subject token with no auth_time cannot prove freshness and is denied in
// enforce (secure default).
func TestExchangeToken_StepUpEnforceDeniesMissingAuthTime(t *testing.T) {
	svc, _, ts := stepUpImpSvc(t, stepUpModeEnforce, 15*time.Minute)

	// GenerateBoundAccessToken omits auth_time.
	subj, err := ts.GenerateBoundAccessToken(&model.User{ID: 100, TokenVersion: 1}, &model.App{ClientID: "subject-app"}, "user", "read write", nil, "")
	if err != nil {
		t.Fatalf("GenerateBoundAccessToken: %v", err)
	}
	form := exForm(subj, "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("want ErrStepUpRequired when auth_time is absent, got %v", err)
	}
}

// Observe records the would-be denial for a stale subject but still issues.
func TestExchangeToken_StepUpObserveIssuesAndAudits(t *testing.T) {
	svc, audit, ts := stepUpImpSvc(t, stepUpModeObserve, 15*time.Minute)

	form := exForm(mintTokenAt(t, ts, 100, "read write", time.Hour), "", "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("observe must still issue: %v", err)
	}
	if resp == nil || resp.AccessToken == "" {
		t.Fatal("observe must issue a token")
	}
	if audit.last.Details["stepup"] != "would_deny" {
		t.Errorf("audit stepup = %v, want would_deny", audit.last.Details["stepup"])
	}
	if audit.last.Details["outcome"] != "issued" {
		t.Errorf("observe outcome = %v, want issued", audit.last.Details["outcome"])
	}
}

// Off (or a zero window) skips the check entirely — a stale subject still issues
// and no step-up telemetry is recorded.
func TestExchangeToken_StepUpOffSkipsCheck(t *testing.T) {
	svc, audit, ts := stepUpImpSvc(t, stepUpModeOff, 15*time.Minute)

	form := exForm(mintTokenAt(t, ts, 100, "read write", time.Hour), "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); err != nil {
		t.Fatalf("off must not deny: %v", err)
	}
	if _, ok := audit.last.Details["stepup_mode"]; ok {
		t.Errorf("off must not record step-up telemetry, got %v", audit.last.Details["stepup_mode"])
	}
}

// Delegation is unaffected by impersonation step-up even when the actor/subject
// authenticated long ago.
func TestExchangeToken_StepUpDoesNotApplyToDelegation(t *testing.T) {
	svc, _, ts := stepUpImpSvc(t, stepUpModeEnforce, 15*time.Minute)

	form := exForm(mintTokenAt(t, ts, 100, "read write", time.Hour), mintTokenAt(t, ts, 200, "read", time.Hour), "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); err != nil {
		t.Fatalf("delegation must not be gated by impersonation step-up: %v", err)
	}
}
