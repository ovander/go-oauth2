package dpop

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoryReplayCache_FirstUseAcceptsReplayRejects(t *testing.T) {
	c := NewMemoryReplayCache(time.Minute)
	defer c.Stop()

	exp := time.Now().Add(MaxAge)
	if !c.CheckAndStore("jti-1", exp) {
		t.Fatal("first use of a jti must be accepted")
	}
	if c.CheckAndStore("jti-1", exp) {
		t.Fatal("second use of the same jti must be rejected")
	}
	if !c.CheckAndStore("jti-2", exp) {
		t.Fatal("a different jti must be accepted")
	}
}

func TestMemoryReplayCache_ExpiredEntryAcceptedAgain(t *testing.T) {
	c := NewMemoryReplayCache(time.Minute)
	defer c.Stop()

	// Store an already-expired entry.
	if !c.CheckAndStore("jti", time.Now().Add(-time.Second)) {
		t.Fatal("first store must be accepted")
	}
	// Because the prior entry is expired, the jti is acceptable again.
	if !c.CheckAndStore("jti", time.Now().Add(MaxAge)) {
		t.Fatal("an expired jti must be acceptable again")
	}
}

func TestMemoryReplayCache_CleanupEvicts(t *testing.T) {
	c := NewMemoryReplayCache(10 * time.Millisecond)
	defer c.Stop()

	c.CheckAndStore("jti", time.Now().Add(5*time.Millisecond))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.seen)
		c.mu.Unlock()
		if n == 0 {
			return // evicted
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected the janitor to evict the expired entry")
}

func TestMemoryReplayCache_ConcurrentSingleWinner(t *testing.T) {
	c := NewMemoryReplayCache(time.Minute)
	defer c.Stop()

	const n = 50
	exp := time.Now().Add(MaxAge)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.CheckAndStore("same-jti", exp) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("exactly one concurrent caller must win, got %d", accepted)
	}
}

func TestVerifyOnce_RejectsReplay(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, jwk, testHTM, testHTU, now, "jti-x")
	c := NewMemoryReplayCache(time.Minute)
	defer c.Stop()

	if _, err := VerifyOnce(proof, testHTM, testHTU, now, c); err != nil {
		t.Fatalf("first use should verify: %v", err)
	}
	if _, err := VerifyOnce(proof, testHTM, testHTU, now, c); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay should be rejected with ErrReplayed, got %v", err)
	}
}

func TestVerifyOnce_InvalidProofNotStored(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	// Method mismatch -> Verify fails; a failed proof must not consume the jti,
	// so a later valid proof with the same jti still succeeds.
	bad := makeProof(t, key, jwk, "GET", testHTU, now, "jti-y")
	c := NewMemoryReplayCache(time.Minute)
	defer c.Stop()

	if _, err := VerifyOnce(bad, testHTM, testHTU, now, c); !errors.Is(err, ErrMethodMismatch) {
		t.Fatalf("want ErrMethodMismatch, got %v", err)
	}
	good := makeProof(t, key, jwk, testHTM, testHTU, now, "jti-y")
	if _, err := VerifyOnce(good, testHTM, testHTU, now, c); err != nil {
		t.Fatalf("a valid proof reusing the jti of a rejected proof should succeed: %v", err)
	}
}
