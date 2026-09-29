package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

// jobRunsTable creates cluster_job_runs as migration 0025 does (the migrate
// package imports this one, so the test cannot call it) and removes this test's
// row afterwards.
func jobRunsTable(t *testing.T, db *gorm.DB, key int64) {
	t.Helper()
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS cluster_job_runs (
		lock_key    BIGINT      PRIMARY KEY,
		last_run_at TIMESTAMPTZ NOT NULL
	)`).Error; err != nil {
		t.Fatalf("create cluster_job_runs: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM cluster_job_runs WHERE lock_key = ?`, key) })
}

// Instances tick on their own schedules. Two instances ticking one after the
// other within an interval must run the job once, not once each — the B5
// promise for key rotation ("once per cluster, not once per instance").
func TestRunGuarded_OncePerIntervalAcrossInstances(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)
	jobRunsTable(t, db, key)

	runs := 0
	job := func(context.Context) error { runs++; return nil }

	runGuarded(db, key, "test_job", time.Hour, job) // instance A's tick
	runGuarded(db, key, "test_job", time.Hour, job) // instance B's tick, moments later
	if runs != 1 {
		t.Fatalf("job ran %d times for two instances within one interval, want 1", runs)
	}

	// Most of an interval later the job is due again, whichever instance ticks.
	if err := db.Exec(`UPDATE cluster_job_runs SET last_run_at = now() - interval '55 minutes'
		WHERE lock_key = ?`, key).Error; err != nil {
		t.Fatal(err)
	}
	runGuarded(db, key, "test_job", time.Hour, job)
	if runs != 2 {
		t.Fatalf("job ran %d times after 55 of 60 minutes, want 2 (due at 90%% of the interval)", runs)
	}
}

// A failed run is not recorded, so the next tick — on any instance — retries
// instead of waiting a whole interval.
func TestRunGuarded_FailedRunIsRetriedNextTick(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)
	jobRunsTable(t, db, key)

	calls := 0
	failing := func(context.Context) error { calls++; return errors.New("boom") }

	runGuarded(db, key, "test_job", time.Hour, failing)
	runGuarded(db, key, "test_job", time.Hour, failing)
	if calls != 2 {
		t.Fatalf("failing job was attempted %d times on two ticks, want 2", calls)
	}
}

func TestJobDue_UsesTheRecordedRun(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)
	jobRunsTable(t, db, key)
	ctx := context.Background()

	due, err := jobDue(ctx, db, key, time.Hour)
	if err != nil || !due {
		t.Fatalf("never-run job: due=%v err=%v, want due", due, err)
	}
	if err := recordRun(ctx, db, key); err != nil {
		t.Fatal(err)
	}
	if due, err = jobDue(ctx, db, key, time.Hour); err != nil || due {
		t.Fatalf("just-run job: due=%v err=%v, want not due", due, err)
	}
	if due, err = jobDue(ctx, db, key, 0); err != nil || !due {
		t.Fatalf("zero gap: due=%v err=%v, want due", due, err)
	}
}
