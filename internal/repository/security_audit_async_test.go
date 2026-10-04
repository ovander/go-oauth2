package repository_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// AUDIT_WRITE_MODE=async: queued rows are appended in batches by one writer.
// The RFC-007 chain must stay linear and every row verifiable, under
// concurrency, with synchronous fallbacks interleaved, and through Close.

var auditTestSecret = []byte("audit-async-test-secret-at-least-32-bytes")

// auditScratchDB creates an empty database next to TEST_DATABASE_URL's with
// only the audit table, and drops it at the end: the chain is checked over the
// whole table, so no other test may write to it.
func auditScratchDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}
	cfg := &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}
	admin, err := gorm.Open(postgres.Open(dsn), cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	name := fmt.Sprintf("socrate_audit_%d", time.Now().UnixNano())
	if err := admin.Exec("CREATE DATABASE " + name).Error; err != nil {
		t.Skipf("cannot create a scratch database (%v)", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := gorm.Open(postgres.Open(u.String()), cfg)
	if err != nil {
		t.Fatalf("connect scratch: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.AutoMigrate(&model.SecurityAuditLog{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return db
}

// countingOutbox records the audit rows it is called for, inside their
// transaction (A3).
type countingOutbox struct {
	mu   sync.Mutex
	seen map[string]int
}

func (o *countingOutbox) WriteOutbox(_ context.Context, tx *gorm.DB, log *model.SecurityAuditLog) error {
	if tx == nil || log.ID == 0 {
		return fmt.Errorf("outbox called outside the row's transaction")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen[log.CorrelationID]++
	return nil
}

func auditRow(i, j int) *model.SecurityAuditLog {
	return &model.SecurityAuditLog{
		EventType:     model.SecurityEventTokenRefreshed,
		Severity:      model.SecuritySeverityInfo,
		Success:       true,
		CorrelationID: fmt.Sprintf("w%d-r%d", i, j),
		Details:       map[string]interface{}{"writer": i, "row": j},
	}
}

// checkAuditTable reads every row and checks the count, the chain and each
// row's HMAC.
func checkAuditTable(t *testing.T, db *gorm.DB, want int) []model.SecurityAuditLog {
	t.Helper()
	var rows []model.SecurityAuditLog
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != want {
		t.Fatalf("%d audit rows, want %d", len(rows), want)
	}
	if broken := repository.VerifyAuditChain(auditTestSecret, rows); len(broken) != 0 {
		t.Fatalf("chain broken at rows %v", broken)
	}
	if tampered := repository.VerifyAuditRows(auditTestSecret, rows); len(tampered) != 0 {
		t.Fatalf("rows failing their HMAC: %v", tampered)
	}
	return rows
}

func TestAsyncAudit_ConcurrentWritersKeepOneChain(t *testing.T) {
	db := auditScratchDB(t)
	base := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, auditTestSecret)
	var batches, batchRows atomic.Int64
	async, err := repository.NewAsyncAuditRepository(base, repository.AsyncAuditConfig{
		OnBatch: func(n int, err error) {
			if err != nil {
				t.Errorf("batch of %d failed: %v", n, err)
			}
			batches.Add(1)
			batchRows.Add(int64(n))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	outbox := &countingOutbox{seen: map[string]int{}}
	async.SetOutboxWriter(outbox)

	const writers, perWriter = 40, 25
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range perWriter {
				row := auditRow(i, j)
				if err := async.Create(context.Background(), row); err != nil {
					t.Errorf("Create: %v", err)
				}
				// The writer works on its own copy: the caller's row is untouched.
				if row.RowHash != "" || row.ID != 0 {
					t.Errorf("caller's row was modified: id=%d", row.ID)
				}
			}
		}()
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rows := checkAuditTable(t, db, writers*perWriter)
	if got := batchRows.Load(); got != writers*perWriter {
		t.Errorf("batches wrote %d rows, want %d", got, writers*perWriter)
	}
	if batches.Load() >= int64(len(rows)) {
		t.Logf("no batching happened (%d batches for %d rows)", batches.Load(), len(rows))
	}
	// Each writer's rows keep their order in the chain.
	last := map[string]int{}
	for _, r := range rows {
		var w, j int
		if _, err := fmt.Sscanf(r.CorrelationID, "w%d-r%d", &w, &j); err != nil {
			t.Fatalf("correlation id %q: %v", r.CorrelationID, err)
		}
		key := fmt.Sprint(w)
		if prev, ok := last[key]; ok && j <= prev {
			t.Fatalf("writer %d: row %d chained after row %d", w, j, prev)
		}
		last[key] = j
		if outbox.seen[r.CorrelationID] != 1 {
			t.Fatalf("outbox called %d times for %s, want once", outbox.seen[r.CorrelationID], r.CorrelationID)
		}
	}
}

// A full queue never drops a row: Create writes synchronously, and those rows
// interleave with the writer's batches on the same, unbroken chain.
func TestAsyncAudit_FullQueueFallsBackToSync(t *testing.T) {
	db := auditScratchDB(t)
	base := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, auditTestSecret)
	var fallbacks atomic.Int64
	async, err := repository.NewAsyncAuditRepository(base, repository.AsyncAuditConfig{
		QueueSize:      1,
		MaxBatch:       4,
		OnSyncFallback: func() { fallbacks.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 10 {
				if err := async.Create(context.Background(), auditRow(i, j)); err != nil {
					t.Errorf("Create: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	checkAuditTable(t, db, 200)
	if fallbacks.Load() == 0 {
		t.Error("a one-slot queue under 20 writers never fell back to a synchronous write")
	}
}

// Close drains what is queued; a Create after Close is written synchronously.
func TestAsyncAudit_CloseDrainsThenWritesSync(t *testing.T) {
	db := auditScratchDB(t)
	base := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, auditTestSecret)
	async, err := repository.NewAsyncAuditRepository(base, repository.AsyncAuditConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for j := range 50 {
		if err := async.Create(context.Background(), auditRow(0, j)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if async.Pending() != 0 {
		t.Fatalf("%d rows still queued after Close", async.Pending())
	}
	checkAuditTable(t, db, 50)

	if err := async.Create(context.Background(), auditRow(1, 0)); err != nil {
		t.Fatalf("Create after Close: %v", err)
	}
	checkAuditTable(t, db, 51) // written before Create returned
	if err := async.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// One row the database refuses does not lose the rest of its batch: the batch
// is retried row by row.
func TestAsyncAudit_BadRowDoesNotLoseTheBatch(t *testing.T) {
	db := auditScratchDB(t)
	base := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, auditTestSecret)
	async, err := repository.NewAsyncAuditRepository(base, repository.AsyncAuditConfig{MaxBatch: 64})
	if err != nil {
		t.Fatal(err)
	}
	for j := range 30 {
		row := auditRow(0, j)
		if j == 15 {
			row.EventType = model.SecurityEventType(strings.Repeat("x", 80)) // over varchar(50)
		}
		if err := async.Create(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	checkAuditTable(t, db, 29)
}

func TestAsyncAudit_NeedsTheGormRepository(t *testing.T) {
	if _, err := repository.NewAsyncAuditRepository(nil, repository.AsyncAuditConfig{}); err == nil {
		t.Fatal("wrapping something else than the GORM audit repository must fail")
	}
}
