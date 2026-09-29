// Package service — tests for the shared audit-row builder used by the direct
// (hot-path) audit writers, focusing on RFC-008 correlation stamping.
package service

import (
	"context"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
)

func TestNewSecurityAuditLog_StampsCorrelationAndFields(t *testing.T) {
	t.Parallel()
	uid := uint(42)
	aid := uint(7)
	ctx := context.WithValue(context.Background(), contextkeys.RequestIDKey, "corr-hot-1")

	log := newSecurityAuditLog(ctx, model.SecurityEventLoginFailed, &uid, &aid, "1.2.3.4", "agent", false, map[string]interface{}{"k": "v"})

	if log.CorrelationID != "corr-hot-1" {
		t.Errorf("CorrelationID = %q, want corr-hot-1", log.CorrelationID)
	}
	// Severity must be derived for the event (login_failed -> warning).
	if log.Severity != model.SecuritySeverityWarning {
		t.Errorf("Severity = %q, want warning", log.Severity)
	}
	if log.EventType != model.SecurityEventLoginFailed || log.UserID == nil || *log.UserID != 42 ||
		log.AppID == nil || *log.AppID != 7 || log.IPAddress != "1.2.3.4" || log.UserAgent != "agent" ||
		log.Success != false || log.Details["k"] != "v" || log.CreatedAt.IsZero() {
		t.Errorf("unexpected row mapping: %+v", log)
	}
}

func TestNewSecurityAuditLog_NoCorrelation_WhenAbsent(t *testing.T) {
	t.Parallel()
	log := newSecurityAuditLog(context.Background(), model.SecurityEventLogout, nil, nil, "", "", true, nil)
	if log.CorrelationID != "" {
		t.Errorf("CorrelationID = %q, want empty", log.CorrelationID)
	}
	if log.Severity != model.SecuritySeverityInfo {
		t.Errorf("Severity = %q, want info (successful logout)", log.Severity)
	}
}
