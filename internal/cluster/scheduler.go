package cluster

import (
	"context"
	"sync"
	"time"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// Job is one unit of periodic background work.
type Job func(context.Context) error

// Every runs job on a ticker, but only on the instance that wins the advisory
// lock for that tick. It returns a stop function.
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
				runGuarded(db, key, name, job)
			}
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(stop) }) }
}

// runGuarded executes one tick, under the lock when a database is configured.
func runGuarded(db *gorm.DB, key int64, name string, job Job) {
	ctx := context.Background()

	if db == nil {
		if err := job(ctx); err != nil {
			logger.WithFields(logger.Fields{"job": name, "error": err.Error()}).
				Warn("B5: scheduled job failed")
		}
		return
	}

	ran, err := TryWithLock(ctx, db, key, job)
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
	}
}
