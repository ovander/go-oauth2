// Package service — tests that confidential-client authentication failures at
// the token endpoint are audited (RFC-007 / RFC 6749 §3.2.1).
package service

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

func confidentialApp(t *testing.T) *model.App {
	t.Helper()
	hash, err := auth.HashClientSecret("right-secret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	return &model.App{
		ID:               1,
		ClientID:         "conf",
		ClientSecretHash: hash,
		Active:           true,
		RedirectURIs:     model.StringArray{"https://app.example.com/cb"},
	}
}

// client_credentials grant: a wrong/missing secret is audited as client_auth_failed.
func TestAudit_ClientCredentials_BadSecret(t *testing.T) {
	svc := newCrit02Service(t, confidentialApp(t))
	audit := &captureAuditRepo{}
	svc.auditRepo = audit

	// Wrong secret.
	if _, err := svc.handleClientCredentialsGrant(context.Background(), dto.TokenRequest{Scope: "api"}, "conf", "wrong"); err == nil {
		t.Fatal("expected an error for a wrong secret")
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventClientAuthFailed {
		t.Fatalf("want client_auth_failed audited, got %+v", audit.last)
	}
	if audit.last.Details["reason"] != "invalid_secret" {
		t.Errorf("reason = %v, want invalid_secret", audit.last.Details["reason"])
	}

	// Missing secret.
	audit.last = nil
	if _, err := svc.handleClientCredentialsGrant(context.Background(), dto.TokenRequest{Scope: "api"}, "conf", ""); err == nil {
		t.Fatal("expected an error for a missing secret")
	}
	if audit.last == nil || audit.last.Details["reason"] != "missing_secret" {
		t.Fatalf("want missing_secret audited, got %+v", audit.last)
	}
}

// authorization_code grant: a confidential client presenting a wrong secret is
// audited as client_auth_failed.
func TestAudit_AuthCodeGrant_BadClientSecret(t *testing.T) {
	app := confidentialApp(t)
	svc := newCrit02Service(t, app)
	audit := &captureAuditRepo{}
	svc.auditRepo = audit

	// Seed a non-PKCE code for the confidential client.
	code, err := svc.codeStore.GenerateCode(
		context.Background(),
		5, app.ID, "conf",
		"https://app.example.com/cb", "openid",
		"", "", "", "user", nil,
	)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	req := dto.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "https://app.example.com/cb",
	}
	if _, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "conf", "wrong-secret"); err == nil {
		t.Fatal("expected an error for a wrong client secret")
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventClientAuthFailed {
		t.Fatalf("want client_auth_failed audited, got %+v", audit.last)
	}
	if audit.last.Details["reason"] != "invalid_secret" || audit.last.Success {
		t.Errorf("expected invalid_secret + success=false, got reason=%v success=%v", audit.last.Details["reason"], audit.last.Success)
	}
}
