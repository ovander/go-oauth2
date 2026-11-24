package service

import (
	"context"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// scanRepo is a mock SecurityAuditLogRepository and AuditChainReader: it serves
// a fixed set of rows, in id order, and captures violation events written via
// Create.
type scanRepo struct {
	repository.SecurityAuditLogRepository
	rows        []model.SecurityAuditLog
	created     []*model.SecurityAuditLog
	headProblem string
}

func (r *scanRepo) AuditChainWindow(_ context.Context, _ time.Time) (repository.AuditChainWindow, error) {
	if len(r.rows) == 0 {
		return repository.AuditChainWindow{}, nil
	}
	return repository.AuditChainWindow{FirstID: r.rows[0].ID, LastID: r.rows[len(r.rows)-1].ID}, nil
}

func (r *scanRepo) AuditChainRows(_ context.Context, afterID, upTo uint, limit int) ([]model.SecurityAuditLog, error) {
	var out []model.SecurityAuditLog
	for _, row := range r.rows {
		if row.ID > afterID && row.ID <= upTo && len(out) < limit {
			out = append(out, row)
		}
	}
	return out, nil
}

func (r *scanRepo) AuditChainHeadProblem(context.Context) (uint, string, string, error) {
	if r.headProblem != "" {
		return 7, "abc", r.headProblem, nil
	}
	return 0, "", "", nil
}

func (r *scanRepo) Create(_ context.Context, log *model.SecurityAuditLog) error {
	r.created = append(r.created, log)
	return nil
}

var scanSecret = []byte("integrity-secret-key-at-least-32-bytes-long!!")

func TestScan_RecordsViolationForTamperedRow(t *testing.T) {
	t.Parallel()
	// One unverifiable (no hash) row and one tampered row (bogus hash).
	repo := &scanRepo{rows: []model.SecurityAuditLog{
		{ID: 1, EventType: model.SecurityEventLoginSuccess, RowHash: ""},
		{ID: 2, EventType: model.SecurityEventLoginFailed, RowHash: "deadbeef"},
	}}
	scanner := NewAuditIntegrityScanner(repo, repo, scanSecret)

	checked, violations, err := scanner.Scan(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if checked != 2 {
		t.Errorf("checked = %d, want 2", checked)
	}
	if violations != 1 {
		t.Fatalf("violations = %d, want 1", violations)
	}
	if len(repo.created) != 1 {
		t.Fatalf("violation events written = %d, want 1", len(repo.created))
	}
	ev := repo.created[0]
	if ev.EventType != model.SecurityEventAuditIntegrityViolation || ev.Severity != model.SecuritySeverityCritical {
		t.Errorf("violation event type/severity = %q/%q", ev.EventType, ev.Severity)
	}
	if id, _ := ev.Details["tampered_row_id"].(uint); id != 2 {
		t.Errorf("tampered_row_id = %v, want 2", ev.Details["tampered_row_id"])
	}
}

func TestScan_CleanDataset_NoViolations(t *testing.T) {
	t.Parallel()
	repo := &scanRepo{rows: []model.SecurityAuditLog{{ID: 1, RowHash: ""}}}
	scanner := NewAuditIntegrityScanner(repo, repo, scanSecret)

	checked, violations, err := scanner.Scan(context.Background(), time.Now().Add(-time.Hour))
	if err != nil || checked != 1 || violations != 0 || len(repo.created) != 0 {
		t.Errorf("Scan(clean) = (checked=%d, viol=%d, err=%v, created=%d), want (1,0,nil,0)",
			checked, violations, err, len(repo.created))
	}
}

func TestScan_EmptySecret_NoOp(t *testing.T) {
	t.Parallel()
	repo := &scanRepo{rows: []model.SecurityAuditLog{{ID: 1, RowHash: "x"}}}
	scanner := NewAuditIntegrityScanner(repo, repo, nil)

	checked, violations, err := scanner.Scan(context.Background(), time.Now().Add(-time.Hour))
	if checked != 0 || violations != 0 || err != nil {
		t.Errorf("Scan(no secret) = (%d,%d,%v), want (0,0,nil)", checked, violations, err)
	}
}

func TestScan_ReportsTheChainHeadProblem(t *testing.T) {
	t.Parallel()
	repo := &scanRepo{headProblem: repository.ChainHeadRowRemoved}
	scanner := NewAuditIntegrityScanner(repo, repo, scanSecret)

	_, violations, err := scanner.Scan(context.Background(), time.Now().Add(-time.Hour))
	if err != nil || violations != 1 || len(repo.created) != 1 {
		t.Fatalf("Scan = (viol=%d, err=%v, created=%d), want one violation", violations, err, len(repo.created))
	}
	if got := repo.created[0].Details["chain_head"]; got != repository.ChainHeadRowRemoved {
		t.Errorf("chain_head = %v, want %s", got, repository.ChainHeadRowRemoved)
	}
	if got := repo.created[0].Details["head_row_id"]; got != uint(7) {
		t.Errorf("head_row_id = %v, want 7", got)
	}
}
