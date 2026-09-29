package cluster

import (
	"context"
	"sync"
	"time"

	"github.com/ovander/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// Job is one unit of periodic background work.
type Job func(context.Context) error

// Every runs job on a ticker, at most once per interval across the cluster. It
// returns a stop function.
//
// Instances tick on their own schedules (each ticker starts at its instance's
// boot), so the advisory lock alone — which only stops two instances running
// the job at the same moment — would let every instance run it once per
// interval. Under the lock, the job therefore runs only if its last completed
// run, recorded cluster-wide in cluster_job_runs, is older than most of an
// interval. A failed run is not recorded, so the next tick retries it.
//
// Every instance keeps ticking and keeps trying, so there is no leader to elect,
// promote or fail over: whoever gets the lock does the work, and if that
// instance dies mid-job its connection drops, the lock disappears, and the next
// tick is contested normally. A crashed leader costs one interval, not an
// outage.
//
// With db nil — the single-instance case, or a deployment that has not opted
// into shared state — the job simply runs on every tick, exactly as it did
// before this existed.
func Every(db *gorm.DB, key int64, name string, interval time.Duration, job Job) func() {
	if interval <= 0 || job == nil {
		return func() {}
	}

	stop := make(chan struct{})
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				runGuarded(db, key, name, interval, job)
			}
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(stop) }) }
}

// dueFraction of the interval must have passed since the last completed run
// before the job runs again. Below 1 so that ticker jitter never makes an
// instance skip its own next tick; high enough that a second instance ticking
// shortly after the first skips.
const dueFraction = 0.9

// runGuarded executes one tick, under the lock when a database is configured.
func runGuarded(db *gorm.DB, key int64, name string, interval time.Duration, job Job) {
	ctx := context.Background()
	if db == nil {
		if err := job(ctx); err != nil {
			logger.WithFields(logger.Fields{"job": name, "error": err.Error()}).
				Warn("B5: scheduled job failed")
		}
		return
	}

	notDue := false
	ran, err := TryWithLock(ctx, db, key, func(ctx context.Context) error {
		due, err := jobDue(ctx, db, key, time.Duration(float64(interval)*dueFraction))
		if err != nil {
			// Without the record (e.g. migration 0025 not applied yet) fall back to
			// the lock-only behaviour rather than silently stopping the job.
			logger.WithFields(logger.Fields{"job": name, "error": err.Error()}).
				Warn("B5: cannot read the job's last run; running this tick")
		} else if !due {
			notDue = true
			return nil
		}
		if err := job(ctx); err != nil {
			return err
		}
		if err := recordRun(ctx, db, key); err != nil {
			logger.WithFields(logger.Fields{"job": name, "error": err.Error()}).
				Warn("B5: job ran but its completion could not be recorded")
		}
		return nil
	})
	switch {
	case err != nil:
		logger.WithFields(logger.Fields{"job": name, "error": err.Error()}).
			Warn("B5: scheduled job failed")
	case !ran:
		// Another instance is running this tick. Expected and unremarkable, so
		// debug rather than info: at a one-minute interval across three
		// instances this would otherwise be two log lines a minute forever.
		logger.WithFields(logger.Fields{"job": name}).
			Debug("B5: another instance holds the job lock for this tick")
	case notDue:
		logger.WithFields(logger.Fields{"job": name}).
			Debug("B5: another instance already ran the job this interval")
	}
}

// jobDue reports whether the job guarded by key last completed more than gap
// ago (or never). It uses the database clock, so instances whose clocks
// disagree still agree on the answer.
func jobDue(ctx context.Context, db *gorm.DB, key int64, gap time.Duration) (bool, error) {
	var row struct{ Recent bool }
	res := db.WithContext(ctx).Raw(
		`SELECT last_run_at > now() - make_interval(secs => ?) AS recent
		   FROM cluster_job_runs WHERE lock_key = ?`, gap.Seconds(), key).Scan(&row)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 0 || !row.Recent, nil
}

// recordRun stamps the job guarded by key as completed now (database clock).
func recordRun(ctx context.Context, db *gorm.DB, key int64) error {
	return db.WithContext(ctx).Exec(
		`INSERT INTO cluster_job_runs (lock_key, last_run_at) VALUES (?, now())
		 ON CONFLICT (lock_key) DO UPDATE SET last_run_at = EXCLUDED.last_run_at`, key).Error
}
