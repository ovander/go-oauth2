package service

import (
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// StartSchedule must run scans and stop cleanly (no panic, no goroutine leak).
func TestStartSchedule_RunsAndStops(t *testing.T) {
	t.Parallel()
	repo := &scanRepo{rows: []model.SecurityAuditLog{{ID: 1, RowHash: "deadbeef"}}}
	scanner := NewAuditIntegrityScanner(repo, scanSecret)

	stop := scanner.StartSchedule(20*time.Millisecond, time.Hour)
	time.Sleep(70 * time.Millisecond) // allow a few scans
	stop()                            // blocks until the goroutine exits

	// At least one scan ran and recorded the tampered row's violation event.
	if len(repo.created) == 0 {
		t.Error("expected the scheduled scan to record at least one violation event")
	}
}

// A lookback <= 0 must fall back to a default (no panic) and still run.
func TestStartSchedule_ZeroLookbackFallsBack(t *testing.T) {
	t.Parallel()
	repo := &scanRepo{rows: []model.SecurityAuditLog{{ID: 1, RowHash: ""}}}
	scanner := NewAuditIntegrityScanner(repo, scanSecret)

	stop := scanner.StartSchedule(20*time.Millisecond, 0)
	time.Sleep(40 * time.Millisecond)
	stop() // must return promptly without panic
}
