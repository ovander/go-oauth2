// Package main — tests for RFC-002 / EPIC-3 key-rotation wiring (#12).
//
// These exercise the bootstrap-level wiring without a database: the retention
// resolution helper and the graceful-shutdown contract for the rotation
// goroutine.
package main

import (
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/shared/auth"
)

func TestKeyRetentionFor_UsesConfiguredWhenPositive(t *testing.T) {
	t.Parallel()
	got := keyRetentionFor(48*time.Hour, 7*24*time.Hour)
	if got != 48*time.Hour {
		t.Errorf("keyRetentionFor(48h, 7d) = %v, want 48h", got)
	}
}

func TestKeyRetentionFor_FallsBackToRefreshTTL(t *testing.T) {
	t.Parallel()
	refresh := 7 * 24 * time.Hour
	for _, retention := range []time.Duration{0, -time.Hour} {
		if got := keyRetentionFor(retention, refresh); got != refresh {
			t.Errorf("keyRetentionFor(%v, %v) = %v, want %v", retention, refresh, got, refresh)
		}
	}
}

// Stop() must be nil-safe when scheduled rotation is disabled.
func TestApp_Stop_NilKeyRotationStop_NoPanic(t *testing.T) {
	t.Parallel()
	app := &App{} // keyRotationStop is nil
	app.Stop()    // must not panic
}

// Stop() must invoke keyRotationStop exactly once when set.
func TestApp_Stop_InvokesKeyRotationStop(t *testing.T) {
	t.Parallel()
	called := 0
	app := &App{keyRotationStop: func() { called++ }}

	app.Stop()

	if called != 1 {
		t.Errorf("keyRotationStop called %d times, want 1", called)
	}
}

// Integration with the real KeyManager stop contract: the stop function
// returned by the schedule is safe to wire into App.Stop().
func TestApp_Stop_StopsRealRotationSchedule(t *testing.T) {
	t.Parallel()
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	app := &App{
		keyRotationStop: km.StartRotationScheduleWithRetention(time.Hour, time.Hour),
	}
	// Must return promptly and not panic (blocks until the goroutine exits).
	app.Stop()
}
