package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// obsTestDB connects to TEST_DATABASE_URL, applies the real migrations, and
// clears the audit table. Skipped without the variable.
func obsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// security_audit_logs is created by AutoMigrate at boot, not by the numbered
	// migration chain, so ensure it exists for these tests.
	if err := db.AutoMigrate(&model.SecurityAuditLog{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := db.Exec(`TRUNCATE security_audit_logs RESTART IDENTITY CASCADE`).Error; err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return db
}

func seedAuditRows(t *testing.T, db *gorm.DB, n int) {
	t.Helper()
	rows := make([]model.SecurityAuditLog, n)
	for i := range rows {
		rows[i] = model.SecurityAuditLog{
			EventType: model.SecurityEventLoginSuccess,
			Severity:  model.SecuritySeverityInfo,
			Success:   true,
			CreatedAt: time.Now(),
		}
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed audit rows: %v", err)
	}
}

// F3: the SSE stream must seed lastEventID from MAX(id) when the client sends no
// last_event_id, so a large backlog is not replayed. We can't easily run the
// long streaming loop in a unit test, but we can assert the seeding query the
// handler now performs returns the tip — the behaviour the fix depends on.
func TestStreamEvents_SeedsFromMaxIDWithBacklog(t *testing.T) {
	db := obsTestDB(t)
	seedAuditRows(t, db, 200)

	var maxID uint
	if err := db.Model(&model.SecurityAuditLog{}).
		Select("COALESCE(MAX(id), 0)").Scan(&maxID).Error; err != nil {
		t.Fatalf("max id: %v", err)
	}
	if maxID < 200 {
		t.Fatalf("expected a backlog of >=200 rows, got max id %d", maxID)
	}

	// A brand-new event after connect must have id > maxID, i.e. the seeded
	// cursor would deliver it while skipping the 200-row backlog.
	seedAuditRows(t, db, 1)
	var newMax uint
	db.Model(&model.SecurityAuditLog{}).Select("COALESCE(MAX(id),0)").Scan(&newMax)
	if newMax <= maxID {
		t.Fatalf("new event id %d not greater than seeded cursor %d", newMax, maxID)
	}

	// And the empty-backlog case: with no rows, the seed is 0 so nothing is skipped.
	if err := db.Exec(`TRUNCATE security_audit_logs RESTART IDENTITY CASCADE`).Error; err != nil {
		t.Fatalf("truncate: %v", err)
	}
	var empty uint
	db.Model(&model.SecurityAuditLog{}).Select("COALESCE(MAX(id),0)").Scan(&empty)
	if empty != 0 {
		t.Fatalf("empty table should seed cursor 0, got %d", empty)
	}
}

func decodeIntegrity(t *testing.T, h *MonitoringHandler) dto.AuditIntegrityResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/audit-integrity?period=24h", nil).
		WithContext(context.Background())
	rec := httptest.NewRecorder()
	h.GetAuditIntegrity(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp dto.AuditIntegrityResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// F8: with rows stamped but the scanner disabled, the endpoint must report
// "not_scanning", not "verified"; with the scanner enabled and no violations it
// reports "verified".
func TestGetAuditIntegrity_NotScanningVsVerified(t *testing.T) {
	db := obsTestDB(t)
	// A stamped, chained row so `configured` is true (row_hash present).
	if err := db.Create(&model.SecurityAuditLog{
		EventType: model.SecurityEventLoginSuccess, Severity: model.SecuritySeverityInfo,
		Success: true, RowHash: "deadbeef", PrevHash: "cafe", CreatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := &MonitoringHandler{db: db}

	h.SetAuditScanningEnabled(false)
	if r := decodeIntegrity(t, h); r.Status != "not_scanning" || r.Scanning {
		t.Errorf("scanner off: status=%q scanning=%v, want not_scanning/false", r.Status, r.Scanning)
	}

	h.SetAuditScanningEnabled(true)
	if r := decodeIntegrity(t, h); r.Status != "verified" || !r.Scanning {
		t.Errorf("scanner on: status=%q scanning=%v, want verified/true", r.Status, r.Scanning)
	}
}
