// Package service — tests for the shared audit-row builder used by the direct
// (hot-path) audit writers, focusing on RFC-008 correlation stamping.
package service

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

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

// The direct audit writers (authService/oauthService) pass no IP or user agent;
// the builder takes both from the context that middleware.ClientIP filled.
func TestNewSecurityAuditLog_AttributesFromContext(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), contextkeys.IPAddressKey, "203.0.113.9")
	ctx = context.WithValue(ctx, contextkeys.UserAgentKey, "Mozilla/5.0 test")

	log := newSecurityAuditLog(ctx, model.SecurityEventLoginSuccess, nil, nil, "", "", true, nil)
	if log.IPAddress != "203.0.113.9" || log.UserAgent != "Mozilla/5.0 test" {
		t.Errorf("IP/UA = %q/%q, want the context values", log.IPAddress, log.UserAgent)
	}

	explicit := newSecurityAuditLog(ctx, model.SecurityEventLoginSuccess, nil, nil, "198.51.100.1", "explicit", true, nil)
	if explicit.IPAddress != "198.51.100.1" || explicit.UserAgent != "explicit" {
		t.Errorf("explicit IP/UA = %q/%q, want the arguments to win", explicit.IPAddress, explicit.UserAgent)
	}

	none := newSecurityAuditLog(context.Background(), model.SecurityEventLoginSuccess, nil, nil, "", "", true, nil)
	if none.IPAddress != "" || none.UserAgent != "" {
		t.Errorf("IP/UA = %q/%q without context values, want empty", none.IPAddress, none.UserAgent)
	}
}

func TestNewSecurityAuditLog_TruncatesUserAgentOnCharacterBoundary(t *testing.T) {
	t.Parallel()
	ua := strings.Repeat("a", maxUserAgentLen-1) + "é" + "tail" // "é" straddles the limit
	ctx := context.WithValue(context.Background(), contextkeys.UserAgentKey, ua)

	log := newSecurityAuditLog(ctx, model.SecurityEventLoginFailed, nil, nil, "", "", false, nil)
	if len(log.UserAgent) > maxUserAgentLen {
		t.Errorf("len(UserAgent) = %d, want <= %d", len(log.UserAgent), maxUserAgentLen)
	}
	if !utf8.ValidString(log.UserAgent) {
		t.Error("UserAgent is not valid UTF-8 after truncation")
	}
	if log.UserAgent != strings.Repeat("a", maxUserAgentLen-1) {
		t.Errorf("UserAgent cut at the wrong place (len %d)", len(log.UserAgent))
	}
}
