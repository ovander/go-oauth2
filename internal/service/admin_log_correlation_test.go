// Package service — tests for RFC-007/RFC-008 correlation-ID stamping on
// admin-action audit logs.
package service

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
)

// captureAdminLogRepo implements AdminLogRepository by embedding the interface
// (only Create is exercised) and records the last created row.
type captureAdminLogRepo struct {
	repository.AdminLogRepository
	last *model.AdminLog
}

func (c *captureAdminLogRepo) Create(_ context.Context, log *model.AdminLog) error {
	c.last = log
	return nil
}

func TestLogAction_StampsCorrelationIDFromContext(t *testing.T) {
	t.Parallel()
	repo := &captureAdminLogRepo{}
	svc := NewAdminLogService(repo)

	ctx := context.WithValue(context.Background(), contextkeys.RequestIDKey, "corr-admin-1")
	if err := svc.LogAction(ctx, 7, nil, nil, model.AdminActionDeleteUser, nil); err != nil {
		t.Fatalf("LogAction: %v", err)
	}
	if repo.last == nil {
		t.Fatal("no admin log row created")
	}
	if repo.last.CorrelationID != "corr-admin-1" {
		t.Errorf("CorrelationID = %q, want corr-admin-1", repo.last.CorrelationID)
	}
}

func TestLogAction_NoCorrelationID_WhenAbsent(t *testing.T) {
	t.Parallel()
	repo := &captureAdminLogRepo{}
	svc := NewAdminLogService(repo)

	if err := svc.LogAction(context.Background(), 7, nil, nil, model.AdminActionUnlockUser, nil); err != nil {
		t.Fatalf("LogAction: %v", err)
	}
	if repo.last.CorrelationID != "" {
		t.Errorf("CorrelationID = %q, want empty", repo.last.CorrelationID)
	}
	// Sanity: the row is otherwise populated.
	if repo.last.AdminID != 7 || repo.last.CreatedAt.IsZero() {
		t.Errorf("unexpected row: %+v", repo.last)
	}
}
