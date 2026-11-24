package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
	"gorm.io/gorm"
)

// #364: removing or blanking the newest audit rows, deleting the chain head,
// and a deletion at a page boundary are all detected, by the scanner over the
// rows the repository really wrote.

type chainRepo interface {
	repository.SecurityAuditLogRepository
	repository.AuditChainReader
	repository.AuditChainAnchorer
}

// chainFixture opens a scratch audit database with the migrations applied
// (audit_chain_head included), an anchored repository and a scanner reading two
// rows a page.
func chainFixture(t *testing.T) (*gorm.DB, chainRepo, *service.AuditIntegrityScanner) {
	t.Helper()
	db := auditScratchDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, auditTestSecret).(chainRepo)
	if err := repo.EnsureAuditChainHead(context.Background()); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	return db, repo, service.NewAuditIntegrityScanner(repo, repo, auditTestSecret).WithPageSize(2)
}

func writeRows(t *testing.T, repo repository.SecurityAuditLogRepository, n int) []uint {
	t.Helper()
	ids := make([]uint, n)
	for i := range ids {
		row := &model.SecurityAuditLog{
			EventType: model.SecurityEventLoginSuccess,
			Severity:  model.SecuritySeverityInfo,
			Success:   true,
			Details:   map[string]interface{}{"seq": i},
		}
		if err := repo.Create(context.Background(), row); err != nil {
			t.Fatalf("create: %v", err)
		}
		ids[i] = row.ID
	}
	return ids
}

// scan runs the scanner over the last hour and returns the violation events it
// wrote.
func scan(t *testing.T, db *gorm.DB, s *service.AuditIntegrityScanner) []model.SecurityAuditLog {
	t.Helper()
	var before uint
	if err := db.Model(&model.SecurityAuditLog{}).Select("COALESCE(MAX(id), 0)").Scan(&before).Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Scan(context.Background(), time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	var events []model.SecurityAuditLog
	if err := db.Where("id > ? AND event_type = ?", before, model.SecurityEventAuditIntegrityViolation).
		Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

// detail returns the events carrying key, with its value as a string.
func detail(events []model.SecurityAuditLog, key string) []string {
	var out []string
	for _, e := range events {
		if v, ok := e.Details[key]; ok {
			out = append(out, toString(v))
		}
	}
	return out
}

// toString formats a detail value: a string as is, a number (a uint when
// written, a float64 when read back from jsonb) in decimal.
func toString(v interface{}) string { return fmt.Sprint(v) }

func uintString(u uint) string { return fmt.Sprint(u) }

func TestAuditChain_CleanLogHasNoViolation(t *testing.T) {
	db, repo, scanner := chainFixture(t)
	writeRows(t, repo, 5)
	if events := scan(t, db, scanner); len(events) != 0 {
		t.Fatalf("clean log: %d violations: %+v", len(events), events)
	}
}

func TestAuditChain_RemovedNewestRowsAreDetected(t *testing.T) {
	db, repo, scanner := chainFixture(t)
	ids := writeRows(t, repo, 5)
	if err := db.Exec("DELETE FROM security_audit_logs WHERE id >= ?", ids[3]).Error; err != nil {
		t.Fatal(err)
	}
	// Before any further append: the head names a row that is gone.
	events := scan(t, db, scanner)
	if got := detail(events, "chain_head"); len(got) != 1 || got[0] != repository.ChainHeadRowRemoved {
		t.Fatalf("chain_head = %v, want [%s]", got, repository.ChainHeadRowRemoved)
	}
	// The next row links to the removed head, so the gap stays visible after
	// it: here, the violation event the scan just wrote.
	events = scan(t, db, scanner)
	breaks := detail(events, "chain_break_row_id")
	if len(breaks) == 0 {
		t.Fatalf("no chain break after the gap: %+v", events)
	}
}

func TestAuditChain_BlankedNewestRowIsDetected(t *testing.T) {
	db, repo, scanner := chainFixture(t)
	ids := writeRows(t, repo, 3)
	newest := ids[2]
	if err := db.Exec("UPDATE security_audit_logs SET row_hash = '' WHERE id = ?", newest).Error; err != nil {
		t.Fatal(err)
	}
	events := scan(t, db, scanner)
	if got := detail(events, "unstamped_row_id"); len(got) != 1 || got[0] != uintString(newest) {
		t.Fatalf("unstamped_row_id = %v, want [%d]", got, newest)
	}
	if got := detail(events, "chain_head"); len(got) != 1 || got[0] != repository.ChainHeadRowChanged {
		t.Fatalf("chain_head = %v, want [%s]", got, repository.ChainHeadRowChanged)
	}
}

func TestAuditChain_DeletionAtAPageBoundaryIsDetected(t *testing.T) {
	db, repo, scanner := chainFixture(t)
	ids := writeRows(t, repo, 6)
	// Two rows a page: deleting the third row makes the fourth the first row
	// of the second page.
	if err := db.Exec("DELETE FROM security_audit_logs WHERE id = ?", ids[2]).Error; err != nil {
		t.Fatal(err)
	}
	events := scan(t, db, scanner)
	if got := detail(events, "chain_break_row_id"); len(got) != 1 || got[0] != uintString(ids[3]) {
		t.Fatalf("chain_break_row_id = %v, want [%d]", got, ids[3])
	}
}

func TestAuditChain_DeletedHeadIsDetected(t *testing.T) {
	db, repo, scanner := chainFixture(t)
	writeRows(t, repo, 2)
	if err := db.Exec("DELETE FROM audit_chain_head").Error; err != nil {
		t.Fatal(err)
	}
	events := scan(t, db, scanner)
	// The scanner reports it; the scan's own write then finds the head
	// missing too and records it in the chain before re-anchoring.
	got := detail(events, "chain_head")
	if len(got) != 2 || got[0] != repository.ChainHeadMissing || got[1] != repository.ChainHeadMissing {
		t.Fatalf("chain_head = %v, want [%s %s]", got, repository.ChainHeadMissing, repository.ChainHeadMissing)
	}
	// Re-anchored: the log is consistent again, apart from the events above.
	if events := scan(t, db, scanner); len(events) != 0 {
		t.Fatalf("after re-anchoring: %+v", events)
	}
}

func TestAuditChain_RetentionKeepsTheHeadRow(t *testing.T) {
	db, repo, scanner := chainFixture(t)
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := repo.Create(context.Background(), &model.SecurityAuditLog{
			EventType: model.SecurityEventLogout, Severity: model.SecuritySeverityInfo, CreatedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := repo.DeleteOlderThan(context.Background(), time.Now())
	if err != nil || n != 2 {
		t.Fatalf("DeleteOlderThan = (%d, %v), want (2, nil): the newest row is kept", n, err)
	}
	if events := scan(t, db, scanner); len(events) != 0 {
		t.Fatalf("after retention: %+v", events)
	}
}

func TestAuditChain_ExistingLogIsAnchoredAtStartup(t *testing.T) {
	db := auditScratchDB(t)
	// Rows written before migration 0033.
	before := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, auditTestSecret)
	writeRows(t, before, 3)
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, auditTestSecret).(chainRepo)
	if err := repo.EnsureAuditChainHead(context.Background()); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	writeRows(t, repo, 2)
	scanner := service.NewAuditIntegrityScanner(repo, repo, auditTestSecret)
	if events := scan(t, db, scanner); len(events) != 0 {
		t.Fatalf("upgraded log: %+v", events)
	}
	checkAuditTable(t, db, 5)
}
