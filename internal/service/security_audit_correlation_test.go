// Package service — tests for RFC-007/RFC-008 correlation-ID stamping on
// security audit events.
package service

import (
	"context"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// captureAuditRepo implements SecurityAuditLogRepository by embedding the
// interface (only Create is exercised) and records the last created row.
type captureAuditRepo struct {
	repository.SecurityAuditLogRepository
	last *model.SecurityAuditLog
}

func (c *captureAuditRepo) Create(_ context.Context, log *model.SecurityAuditLog) error {
	c.last = log
	return nil
}

func TestLog_StampsCorrelationIDFromContext(t *testing.T) {
	t.Parallel()
	repo := &captureAuditRepo{}
	svc := NewSecurityAuditService(repo)

	ctx := context.WithValue(context.Background(), contextkeys.RequestIDKey, "corr-xyz")
	if err := svc.Log(ctx, SecurityEvent{EventType: model.SecurityEventLoginSuccess, Success: true}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if repo.last == nil {
		t.Fatal("no audit row created")
	}
	if repo.last.CorrelationID != "corr-xyz" {
		t.Errorf("CorrelationID = %q, want corr-xyz", repo.last.CorrelationID)
	}
}

func TestLog_ExplicitCorrelationIDWins(t *testing.T) {
	t.Parallel()
	repo := &captureAuditRepo{}
	svc := NewSecurityAuditService(repo)

	ctx := context.WithValue(context.Background(), contextkeys.RequestIDKey, "from-ctx")
	err := svc.Log(ctx, SecurityEvent{
		EventType:     model.SecurityEventLoginFailed,
		CorrelationID: "explicit",
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if repo.last.CorrelationID != "explicit" {
		t.Errorf("CorrelationID = %q, want explicit (override should win)", repo.last.CorrelationID)
	}
}

func TestLog_NoCorrelationID_WhenAbsent(t *testing.T) {
	t.Parallel()
	repo := &captureAuditRepo{}
	svc := NewSecurityAuditService(repo)

	if err := svc.Log(context.Background(), SecurityEvent{EventType: model.SecurityEventLogout}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if repo.last.CorrelationID != "" {
		t.Errorf("CorrelationID = %q, want empty", repo.last.CorrelationID)
	}
}
