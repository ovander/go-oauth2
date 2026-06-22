package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// countingUsedTokenRepo records how many times DeleteExpired was called and how
// many rows it reports pruning.
type countingUsedTokenRepo struct {
	calls   int32
	deleted int64
}

func (r *countingUsedTokenRepo) MarkAsUsed(_ context.Context, _, _ string, _ uint, _ time.Time) error {
	return nil
}
func (r *countingUsedTokenRepo) IsUsed(_ context.Context, _ string) (bool, error) { return false, nil }
func (r *countingUsedTokenRepo) DeleteExpired(_ context.Context) (int64, error) {
	atomic.AddInt32(&r.calls, 1)
	return r.deleted, nil
}

// Cleanup delegates to DeleteExpired and is nil-safe.
func TestUsedTokenCleaner_Cleanup(t *testing.T) {
	t.Parallel()
	repo := &countingUsedTokenRepo{deleted: 3}
	n, err := NewUsedTokenCleaner(repo).Cleanup(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("Cleanup = (%d, %v), want (3, nil)", n, err)
	}

	// Nil repo is a no-op, not a panic.
	if n, err := NewUsedTokenCleaner(nil).Cleanup(context.Background()); err != nil || n != 0 {
		t.Fatalf("nil-repo Cleanup = (%d, %v), want (0, nil)", n, err)
	}
}

// StartSchedule must run the cleanup on a timer and stop cleanly.
func TestUsedTokenCleaner_StartScheduleRunsAndStops(t *testing.T) {
	t.Parallel()
	repo := &countingUsedTokenRepo{deleted: 1}
	stop := NewUsedTokenCleaner(repo).StartSchedule(20 * time.Millisecond)
	time.Sleep(70 * time.Millisecond) // allow a few sweeps
	stop()                            // blocks until the goroutine exits

	if atomic.LoadInt32(&repo.calls) == 0 {
		t.Error("expected the scheduled cleanup to call DeleteExpired at least once")
	}

	// After stop, no further calls should occur.
	settled := atomic.LoadInt32(&repo.calls)
	time.Sleep(40 * time.Millisecond)
	if atomic.LoadInt32(&repo.calls) != settled {
		t.Error("cleanup kept running after stop()")
	}
}
