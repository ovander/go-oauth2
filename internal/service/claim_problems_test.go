package service

import (
	"context"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// claimAuditRepo captures Create; the embedded nil interface fails loudly on
// anything else.
type claimAuditRepo struct {
	repository.SecurityAuditLogRepository
	rows chan *model.SecurityAuditLog
}

func (r *claimAuditRepo) Create(_ context.Context, l *model.SecurityAuditLog) error {
	r.rows <- l
	return nil
}

func (r *claimAuditRepo) next(t *testing.T) *model.SecurityAuditLog {
	t.Helper()
	select {
	case l := <-r.rows:
		return l
	case <-time.After(2 * time.Second):
		t.Fatal("no audit row written")
		return nil
	}
}

func (r *claimAuditRepo) none(t *testing.T) {
	t.Helper()
	select {
	case l := <-r.rows:
		t.Fatalf("unexpected audit row: %+v", l)
	case <-time.After(50 * time.Millisecond):
	}
}

func missing(user uint, claim string) auth.ClaimIssueProblem {
	return auth.ClaimIssueProblem{Kind: auth.ClaimProblemMissing, UserID: user, AppID: 3, ClientID: "lakebridge-portal",
		Claim: claim, Source: "user.attributes." + claim, Target: "access"}
}

func TestClaimProblemRecorder_RecordsOncePerWindow(t *testing.T) {
	repo := &claimAuditRepo{rows: make(chan *model.SecurityAuditLog, 10)}
	r := NewClaimProblemRecorder(repo, time.Hour, 100)
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }

	r.Report(missing(42, "tenant_id"))
	row := repo.next(t)
	if row.EventType != model.SecurityEventCustomClaimMissing || row.Severity != model.SecuritySeverityWarning ||
		row.UserID == nil || *row.UserID != 42 || row.AppID == nil || *row.AppID != 3 ||
		row.Details["claim"] != "tenant_id" || row.Details["client_id"] != "lakebridge-portal" {
		t.Fatalf("row = %+v", row)
	}

	// Every refresh repeats it: not recorded again within the hour...
	r.Report(missing(42, "tenant_id"))
	repo.none(t)
	// ...but another user, or another claim, is.
	r.Report(missing(43, "tenant_id"))
	repo.next(t)
	r.Report(missing(42, "portal_role"))
	repo.next(t)

	// After the window it is recorded again.
	now = now.Add(time.Hour)
	r.Report(missing(42, "tenant_id"))
	repo.next(t)
}

func TestClaimProblemRecorder_DroppedSet(t *testing.T) {
	repo := &claimAuditRepo{rows: make(chan *model.SecurityAuditLog, 10)}
	r := NewClaimProblemRecorder(repo, time.Hour, 100)
	r.Report(auth.ClaimIssueProblem{Kind: auth.ClaimProblemDropped, UserID: 42, AppID: 3, ClientID: "c", Target: "access", Size: 4000})
	row := repo.next(t)
	if row.EventType != model.SecurityEventCustomClaimsDropped || row.Severity != model.SecuritySeverityError ||
		row.Details["size"] != 4000 || row.Details["max_bytes"] != auth.MaxCustomClaimsBytes {
		t.Fatalf("row = %+v", row)
	}
}

// The memory is bounded: when it is full of unexpired entries, new problems
// are not recorded; once entries expire, they are again.
func TestClaimProblemRecorder_BoundedMemory(t *testing.T) {
	repo := &claimAuditRepo{rows: make(chan *model.SecurityAuditLog, 10)}
	r := NewClaimProblemRecorder(repo, time.Hour, 2)
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }

	r.Report(missing(1, "a"))
	r.Report(missing(2, "a"))
	repo.next(t)
	repo.next(t)
	r.Report(missing(3, "a"))
	repo.none(t)

	now = now.Add(time.Hour)
	r.Report(missing(3, "a"))
	repo.next(t)
}
