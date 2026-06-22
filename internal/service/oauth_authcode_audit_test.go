// Package service — tests that security-relevant authorization-code grant
// failures are audited (RFC-007 coverage of sensitive actions).
package service

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

// An invalid / already-used authorization code is audited as auth_code_failed.
func TestAudit_AuthCodeGrant_InvalidCode(t *testing.T) {
	app := publicClientApp()
	svc := newCrit02Service(t, app)
	audit := &captureAuditRepo{}
	svc.auditRepo = audit

	req := dto.TokenRequest{
		GrantType:   "authorization_code",
		Code:        "totally-bogus-code",
		RedirectURI: "https://spa.example.com/cb",
	}
	if _, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "public-spa", ""); err == nil {
		t.Fatal("expected an error for a bogus code")
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventAuthCodeFailed {
		t.Fatalf("want auth_code_failed audited, got %+v", audit.last)
	}
	if audit.last.Details["reason"] != "invalid_or_used_code" {
		t.Errorf("reason = %v, want invalid_or_used_code", audit.last.Details["reason"])
	}
}

// A PKCE verification failure is audited as pkce_validation_failed.
func TestAudit_AuthCodeGrant_PKCEFailure(t *testing.T) {
	app := publicClientApp()
	svc := newCrit02Service(t, app)
	audit := &captureAuditRepo{}
	svc.auditRepo = audit

	code, _ := seedCodeWithPKCE(t, svc, "public-spa", "https://spa.example.com/cb", 77)
	req := dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://spa.example.com/cb",
		CodeVerifier: "wrong-verifier-that-does-not-match-the-challenge",
	}
	if _, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "public-spa", ""); err == nil {
		t.Fatal("expected a PKCE error")
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventPKCEValidationFail {
		t.Fatalf("want pkce_validation_failed audited, got %+v", audit.last)
	}
	if audit.last.Details["reason"] != "verification_failed" {
		t.Errorf("reason = %v, want verification_failed", audit.last.Details["reason"])
	}
	if audit.last.Success {
		t.Error("a PKCE failure audit row must have success=false")
	}
}

// A client_id mismatch on a valid code is audited as auth_code_failed.
func TestAudit_AuthCodeGrant_ClientMismatch(t *testing.T) {
	app := publicClientApp()
	svc := newCrit02Service(t, app)
	audit := &captureAuditRepo{}
	svc.auditRepo = audit

	code, verifier := seedCodeWithPKCE(t, svc, "public-spa", "https://spa.example.com/cb", 88)
	req := dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://spa.example.com/cb",
		CodeVerifier: verifier,
	}
	// Present a different client_id than the code was issued to.
	if _, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "some-other-client", ""); err == nil {
		t.Fatal("expected a client_id mismatch error")
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventAuthCodeFailed {
		t.Fatalf("want auth_code_failed audited, got %+v", audit.last)
	}
	if audit.last.Details["reason"] != "client_id_mismatch" {
		t.Errorf("reason = %v, want client_id_mismatch", audit.last.Details["reason"])
	}
}
