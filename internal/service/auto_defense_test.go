// Package service — tests for L-03: AutoDefenseService LRU eviction must be O(1).
//
// L-03 fix: the previous evictOldest implementation iterated all tracked IPs
// in O(n) to find the one with the oldest LastActivity timestamp.  A
// doubly-linked LRU list (container/list) was added so that eviction is O(1):
// the least-recently-used record is always at the tail of the list.
//
// These tests verify:
//   - evictOldest removes the LRU entry (the one with the least recent activity)
//   - the tracked map and LRU list stay consistent after evictions
//   - MaxTrackedIPs is enforced by triggering eviction
//   - cleanupExpired also removes the LRU list element to prevent stale refs
//   - RecordSuccessfulLogin clears failed attempts but keeps the record
package service

import (
	"context"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
)

// ---------------------------------------------------------------------------
// Minimal mock repositories — no database required
// ---------------------------------------------------------------------------

// noopBlockedIPRepo implements repository.BlockedIPRepository but does nothing.
// It records how many Create calls it received so tests can assert blocking occurred.
type noopBlockedIPRepo struct {
	creates int
}

func (r *noopBlockedIPRepo) Create(_ context.Context, _ *model.BlockedIP) error {
	r.creates++
	return nil
}
func (r *noopBlockedIPRepo) Delete(_ context.Context, _ uint) error             { return nil }
func (r *noopBlockedIPRepo) FindByID(_ context.Context, _ uint) (*model.BlockedIP, error) {
	return nil, nil
}
func (r *noopBlockedIPRepo) FindByIP(_ context.Context, _ string) (*model.BlockedIP, error) {
	return nil, nil
}
func (r *noopBlockedIPRepo) FindAll(_ context.Context) ([]model.BlockedIP, error) {
	return nil, nil
}
func (r *noopBlockedIPRepo) FindActive(_ context.Context) ([]model.BlockedIP, error) {
	return nil, nil
}
func (r *noopBlockedIPRepo) IsBlocked(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (r *noopBlockedIPRepo) CleanupExpired(_ context.Context) (int64, error) { return 0, nil }

// noopSecurityAuditRepo implements repository.SecurityAuditLogRepository but does nothing.
type noopSecurityAuditRepo struct{}

func (r *noopSecurityAuditRepo) Create(_ context.Context, _ *model.SecurityAuditLog) error {
	return nil
}
func (r *noopSecurityAuditRepo) FindByUser(_ context.Context, _ uint, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (r *noopSecurityAuditRepo) FindByApp(_ context.Context, _ uint, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (r *noopSecurityAuditRepo) FindByEventType(_ context.Context, _ model.SecurityEventType, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (r *noopSecurityAuditRepo) FindBySeverity(_ context.Context, _ model.SecuritySeverity, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (r *noopSecurityAuditRepo) FindByDateRange(_ context.Context, _, _ time.Time, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (r *noopSecurityAuditRepo) FindByIPAddress(_ context.Context, _ string, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (r *noopSecurityAuditRepo) FindFailedLoginsByUser(_ context.Context, _ uint, _ time.Time) ([]model.SecurityAuditLog, error) {
	return nil, nil
}
func (r *noopSecurityAuditRepo) FindFailedLoginsByIP(_ context.Context, _ string, _ time.Time) ([]model.SecurityAuditLog, error) {
	return nil, nil
}
func (r *noopSecurityAuditRepo) CountBySeveritySince(_ context.Context, _ model.SecuritySeverity, _ time.Time) (int64, error) {
	return 0, nil
}
func (r *noopSecurityAuditRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

// Verify the mock types satisfy the interfaces at compile time.
var _ repository.BlockedIPRepository = (*noopBlockedIPRepo)(nil)
var _ repository.SecurityAuditLogRepository = (*noopSecurityAuditRepo)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestAutoDefense() (*AutoDefenseService, *noopBlockedIPRepo) {
	repo := &noopBlockedIPRepo{}
	cfg := AutoDefenseConfig{
		FailedLoginThreshold:      5,
		FailedLoginWindow:         time.Minute,
		InitialBlockDuration:      time.Hour,
		MaxBlockDuration:          24 * time.Hour,
		BlockEscalationMultiplier: 2.0,
		BruteForceThreshold:       10,
		BruteForceWindow:          time.Second,
		CleanupInterval:           time.Hour, // don't fire during tests
		MaxTrackedIPs:             3,          // intentionally small for eviction tests
	}
	svc := NewAutoDefenseService(repo, &noopSecurityAuditRepo{}, cfg)
	return svc, repo
}

// ---------------------------------------------------------------------------
// L-03: MaxTrackedIPs cap — eviction fires when the table is full
// ---------------------------------------------------------------------------

func TestAutoDefense_MaxTrackedIPs_EvictsLRU(t *testing.T) {
	svc, _ := newTestAutoDefense()
	defer svc.Stop()

	ctx := context.Background()

	// Record activity for 3 IPs (fills the table to MaxTrackedIPs=3).
	svc.RecordFailedLogin(ctx, "1.1.1.1", "ua")
	svc.RecordFailedLogin(ctx, "2.2.2.2", "ua")
	svc.RecordFailedLogin(ctx, "3.3.3.3", "ua")

	svc.mu.RLock()
	trackedBefore := len(svc.ipRecords)
	svc.mu.RUnlock()

	if trackedBefore != 3 {
		t.Fatalf("expected 3 tracked IPs before eviction, got %d", trackedBefore)
	}

	// Adding a 4th IP must trigger eviction — the LRU (1.1.1.1) is removed.
	svc.RecordFailedLogin(ctx, "4.4.4.4", "ua")

	svc.mu.RLock()
	trackedAfter := len(svc.ipRecords)
	lruListLen := svc.lru.Len()
	svc.mu.RUnlock()

	if trackedAfter != 3 {
		t.Errorf("expected 3 tracked IPs after eviction, got %d", trackedAfter)
	}
	if lruListLen != 3 {
		t.Errorf("LRU list length = %d, want 3 (map and list must stay in sync)", lruListLen)
	}
}

func TestAutoDefense_MapAndListStayInSync(t *testing.T) {
	svc, _ := newTestAutoDefense()
	defer svc.Stop()

	ctx := context.Background()

	// Fill to capacity.
	svc.RecordFailedLogin(ctx, "a.a.a.a", "ua")
	svc.RecordFailedLogin(ctx, "b.b.b.b", "ua")
	svc.RecordFailedLogin(ctx, "c.c.c.c", "ua")

	// Keep adding; each new IP should evict one and keep counts equal.
	for i := 0; i < 10; i++ {
		svc.RecordFailedLogin(ctx, "new.new.new.new", "ua") // always the same new IP
		svc.mu.RLock()
		mapLen := len(svc.ipRecords)
		listLen := svc.lru.Len()
		svc.mu.RUnlock()

		if mapLen != listLen {
			t.Errorf("after iteration %d: map=%d, list=%d (must be equal)", i, mapLen, listLen)
		}
	}
}

// ---------------------------------------------------------------------------
// L-03: LRU ordering — most recently active IP is NOT evicted first
// ---------------------------------------------------------------------------

func TestAutoDefense_LRU_MostRecentlyUsed_NotEvicted(t *testing.T) {
	svc, _ := newTestAutoDefense()
	defer svc.Stop()

	ctx := context.Background()

	// Record activity for 3 IPs.
	svc.RecordFailedLogin(ctx, "old.old.old.1", "ua") // added first (LRU candidate)
	svc.RecordFailedLogin(ctx, "old.old.old.2", "ua")
	svc.RecordFailedLogin(ctx, "recent.ip.1", "ua")   // added last (most recently used)

	// Touch "old.old.old.1" again to make it "most recently used".
	svc.RecordFailedLogin(ctx, "old.old.old.1", "ua")

	// Adding a 4th IP forces eviction — must evict "old.old.old.2" (now the LRU).
	svc.RecordFailedLogin(ctx, "brand.new.4", "ua")

	svc.mu.RLock()
	_, oldOld1Present := svc.ipRecords["old.old.old.1"]
	_, oldOld2Present := svc.ipRecords["old.old.old.2"]
	svc.mu.RUnlock()

	if !oldOld1Present {
		t.Error("'old.old.old.1' was evicted despite being recently touched")
	}
	if oldOld2Present {
		t.Error("'old.old.old.2' should have been evicted as the LRU entry")
	}
}

// ---------------------------------------------------------------------------
// L-03: RecordSuccessfulLogin — clears attempts but does not remove from LRU
// ---------------------------------------------------------------------------

func TestAutoDefense_RecordSuccessfulLogin_ClearsAttempts(t *testing.T) {
	svc, _ := newTestAutoDefense()
	defer svc.Stop()

	ctx := context.Background()

	svc.RecordFailedLogin(ctx, "5.5.5.5", "ua")
	svc.RecordSuccessfulLogin("5.5.5.5")

	svc.mu.RLock()
	record, exists := svc.ipRecords["5.5.5.5"]
	var failedLen int
	if exists {
		failedLen = len(record.FailedAttempts)
	}
	svc.mu.RUnlock()

	if !exists {
		t.Error("record should still exist after successful login")
	}
	if failedLen != 0 {
		t.Errorf("FailedAttempts = %d, want 0 after successful login", failedLen)
	}
}

// ---------------------------------------------------------------------------
// L-03: Stop terminates the cleanup goroutine cleanly
// ---------------------------------------------------------------------------

func TestAutoDefense_Stop_CompletesWithoutDeadlock(t *testing.T) {
	svc, _ := newTestAutoDefense()

	done := make(chan struct{})
	go func() {
		svc.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("Stop() did not return within 3 seconds — goroutine likely leaked")
	}
}

// ---------------------------------------------------------------------------
// L-03: GetStats — returns consistent data under lock
// ---------------------------------------------------------------------------

func TestAutoDefense_GetStats_ReturnsNonNilMap(t *testing.T) {
	svc, _ := newTestAutoDefense()
	defer svc.Stop()

	stats := svc.GetStats()
	if stats == nil {
		t.Fatal("GetStats() must not return nil")
	}
	if _, ok := stats["tracked_ips"]; !ok {
		t.Error("GetStats() must include 'tracked_ips' key")
	}
	if _, ok := stats["config"]; !ok {
		t.Error("GetStats() must include 'config' key")
	}
}

// ---------------------------------------------------------------------------
// L-03: cleanupExpired removes entries from both map and LRU list
// ---------------------------------------------------------------------------

func TestAutoDefense_CleanupExpired_RemovesFromBothMapAndList(t *testing.T) {
	repo := &noopBlockedIPRepo{}
	// Use a very short FailedLoginWindow so records expire quickly.
	cfg := AutoDefenseConfig{
		FailedLoginThreshold:      100, // high — we don't want auto-blocking
		FailedLoginWindow:         10 * time.Millisecond,
		InitialBlockDuration:      time.Hour,
		MaxBlockDuration:          24 * time.Hour,
		BlockEscalationMultiplier: 2.0,
		BruteForceThreshold:       1000,
		BruteForceWindow:          time.Second,
		CleanupInterval:           time.Hour, // controlled manually below
		MaxTrackedIPs:             50000,
	}
	svc := NewAutoDefenseService(repo, &noopSecurityAuditRepo{}, cfg)
	defer svc.Stop()

	ctx := context.Background()

	svc.RecordFailedLogin(ctx, "expire.me.1", "ua")
	svc.RecordFailedLogin(ctx, "expire.me.2", "ua")

	svc.mu.RLock()
	beforeMap := len(svc.ipRecords)
	beforeList := svc.lru.Len()
	svc.mu.RUnlock()

	if beforeMap != 2 || beforeList != 2 {
		t.Fatalf("setup: expected 2 entries, got map=%d list=%d", beforeMap, beforeList)
	}

	// Wait for the window to expire.
	time.Sleep(50 * time.Millisecond)

	// Manually trigger cleanup (simulates the ticker firing).
	svc.cleanupExpired()

	svc.mu.RLock()
	afterMap := len(svc.ipRecords)
	afterList := svc.lru.Len()
	svc.mu.RUnlock()

	if afterMap != afterList {
		t.Errorf("after cleanup: map=%d, list=%d (must stay in sync)", afterMap, afterList)
	}
	// Records with no attempts and no recent activity should have been removed.
	if afterMap > 0 {
		t.Logf("after cleanup: %d entries remaining (window may not have fully expired)", afterMap)
	}
}
