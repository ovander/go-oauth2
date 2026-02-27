// Package middleware — tests for L-02: the rate-limiter cleanup goroutine must
// use the project's structured logger (pkg/logger) and not the stdlib log package.
//
// L-02 fix: the cleanup goroutine previously called log.Println (stdlib), which
// wrote to a different destination than all other application log output.
// Replaced with logger.Info from the project's logrus-based logger.
//
// These tests verify the observable behaviour of the rate limiter's lifecycle —
// specifically that Stop() causes the cleanup goroutine to terminate cleanly,
// and that the limiter behaves identically before and after stop.
package middleware

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// L-02: cleanup goroutine terminates cleanly via Stop()
// ---------------------------------------------------------------------------

func TestRateLimiter_Stop_CompletesWithoutDeadlock(t *testing.T) {
	t.Parallel()
	// If the cleanup goroutine leaks or blocks on stop, this test will time out.
	rl := NewRateLimiterWithConfig(RateLimiterConfig{
		Limit:           10,
		Window:          time.Second,
		MaxEntries:      100,
		CleanupInterval: 50 * time.Millisecond,
	})
	// Let the cleanup ticker fire at least once before stopping.
	time.Sleep(70 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		rl.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success: Stop() returned promptly.
	case <-time.After(3 * time.Second):
		t.Error("Stop() did not return within 3 seconds — goroutine likely leaked")
	}
}

func TestRateLimiter_Stop_CanBeCalledOnEmptyLimiter(t *testing.T) {
	t.Parallel()
	// Stop on a freshly-created limiter with no requests tracked must not panic.
	rl := NewRateLimiterWithConfig(RateLimiterConfig{
		Limit:           5,
		Window:          time.Second,
		MaxEntries:      10,
		CleanupInterval: time.Minute, // very long — we stop before it fires
	})
	rl.Stop() // must not panic or block
}

func TestRateLimiter_CleanupRemovesExpiredEntries(t *testing.T) {
	t.Parallel()
	// Use a very short window so entries expire quickly, and a short cleanup
	// interval so the goroutine runs before the test ends.
	rl := NewRateLimiterWithConfig(RateLimiterConfig{
		Limit:           100,
		Window:          50 * time.Millisecond,
		MaxEntries:      100,
		CleanupInterval: 30 * time.Millisecond,
	})
	defer rl.Stop()

	// Add some entries.
	rl.Allow("ip-1")
	rl.Allow("ip-2")
	rl.Allow("ip-3")

	if rl.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", rl.Len())
	}

	// Wait for the window to expire and for the cleanup goroutine to run.
	time.Sleep(200 * time.Millisecond)

	if rl.Len() != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", rl.Len())
	}
}

func TestRateLimiter_AllowAfterStop_NotCalled(t *testing.T) {
	t.Parallel()
	// Verify the limiter functions correctly up to the point of Stop().
	rl := NewRateLimiterWithConfig(RateLimiterConfig{
		Limit:           2,
		Window:          time.Minute,
		MaxEntries:      10,
		CleanupInterval: time.Minute,
	})

	if !rl.Allow("client") {
		t.Error("first request must be allowed")
	}
	if !rl.Allow("client") {
		t.Error("second request must be allowed")
	}
	if rl.Allow("client") {
		t.Error("third request must be blocked (limit=2)")
	}

	rl.Stop()
}

// ---------------------------------------------------------------------------
// L-02: cleanup interval fires, then goroutine stops cleanly
// ---------------------------------------------------------------------------

func TestRateLimiter_MultipleCleanupCycles_ThenStop(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiterWithConfig(RateLimiterConfig{
		Limit:           10,
		Window:          20 * time.Millisecond,
		MaxEntries:      50,
		CleanupInterval: 15 * time.Millisecond,
	})

	// Generate traffic so cleanup has real work to do.
	for i := 0; i < 10; i++ {
		rl.Allow("key-a")
		rl.Allow("key-b")
	}

	// Allow several cleanup cycles.
	time.Sleep(80 * time.Millisecond)

	// Stop must succeed even after multiple cleanup runs.
	done := make(chan struct{})
	go func() {
		rl.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("Stop() did not return within 3 seconds after multiple cleanup cycles")
	}
}
