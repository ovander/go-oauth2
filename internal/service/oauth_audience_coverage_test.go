// Package service — tests for EPIC-7 Phase 1 audience-coverage telemetry: token
// issuance audit rows record whether the client has registered audiences, the
// count, and the active audience mode (the parity signal for enabling
// audience-scoped enforcement).
package service

import (
	"context"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

func TestAudienceCoverage_TokenIssued_RecordsRegistration(t *testing.T) {
	hash, err := auth.HashClientSecret("right-secret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	app := &model.App{
		ID:               1,
		ClientID:         "conf",
		ClientSecretHash: hash,
		Active:           true,
		Audiences:        model.StringArray{"https://api.example.com", "https://reports.example.com"},
	}
	svc := newCrit02Service(t, app)
	audit := &captureAuditRepo{}
	svc.auditRepo = audit

	if _, err := svc.handleClientCredentialsGrant(context.Background(), dto.TokenRequest{Scope: "api"}, "conf", "right-secret"); err != nil {
		t.Fatalf("client_credentials issuance failed: %v", err)
	}
	d := audit.last.Details
	if d["audience_registered"] != true {
		t.Errorf("audience_registered = %v, want true", d["audience_registered"])
	}
	if d["audience_count"] != 2 {
		t.Errorf("audience_count = %v, want 2", d["audience_count"])
	}
	if _, ok := d["audience_mode"]; !ok {
		t.Error("audience_mode must be recorded on the issuance audit row")
	}
}

func TestAudienceCoverage_NoAudiences_RecordsFalse(t *testing.T) {
	hash, _ := auth.HashClientSecret("right-secret")
	app := &model.App{ID: 1, ClientID: "conf", ClientSecretHash: hash, Active: true} // no Audiences
	svc := newCrit02Service(t, app)
	audit := &captureAuditRepo{}
	svc.auditRepo = audit

	if _, err := svc.handleClientCredentialsGrant(context.Background(), dto.TokenRequest{Scope: "api"}, "conf", "right-secret"); err != nil {
		t.Fatalf("issuance failed: %v", err)
	}
	if audit.last.Details["audience_registered"] != false || audit.last.Details["audience_count"] != 0 {
		t.Errorf("uncovered client must record registered=false count=0, got %v / %v",
			audit.last.Details["audience_registered"], audit.last.Details["audience_count"])
	}
}
