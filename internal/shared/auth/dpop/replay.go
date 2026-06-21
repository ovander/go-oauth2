package dpop

import (
	"errors"
	"sync"
	"time"
)

// ErrReplayed indicates a DPoP proof whose jti has already been seen within the
// acceptance window — i.e. a replay.
var ErrReplayed = errors.New("dpop: proof replayed (jti already used)")

// ReplayCache records DPoP proof identifiers (jti) for the brief window during
// which a proof is acceptable, so the same proof cannot be replayed. Verify is
// stateless; pair it with a ReplayCache (or use VerifyOnce) to get replay
// protection.
type ReplayCache interface {
	// CheckAndStore atomically records jti when it is not already present and
	// returns true (accepted). If jti is already present and unexpired (a
	// replay) it returns false without modifying the entry. exp is when the
	// entry may be forgotten.
	CheckAndStore(jti string, exp time.Time) bool
}

// MemoryReplayCache is an in-memory ReplayCache with a background janitor that
// evicts expired entries. It is safe for concurrent use. For a single-instance
// deployment this is sufficient; a multi-instance deployment needs a shared
// store (e.g. Redis) implementing the same interface — a later slice.
type MemoryReplayCache struct {
	mu     sync.Mutex
	seen   map[string]time.Time // jti -> expiry
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewMemoryReplayCache creates a cache and starts its cleanup goroutine. A
// cleanupInterval <= 0 falls back to one minute.
func NewMemoryReplayCache(cleanupInterval time.Duration) *MemoryReplayCache {
	if cleanupInterval <= 0 {
		cleanupInterval = time.Minute
	}
	c := &MemoryReplayCache{
		seen:   make(map[string]time.Time),
		stopCh: make(chan struct{}),
	}
	c.wg.Add(1)
	go c.cleanup(cleanupInterval)
	return c
}

// CheckAndStore implements ReplayCache.
func (c *MemoryReplayCache) CheckAndStore(jti string, exp time.Time) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.seen[jti]; ok && e.After(now) {
		return false // active, unexpired entry — replay
	}
	c.seen[jti] = exp
	return true
}

// Stop terminates the cleanup goroutine and blocks until it has exited.
func (c *MemoryReplayCache) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

func (c *MemoryReplayCache) cleanup(interval time.Duration) {
	defer c.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			c.mu.Lock()
			for jti, exp := range c.seen {
				if !exp.After(now) {
					delete(c.seen, jti)
				}
			}
			c.mu.Unlock()
		}
	}
}

// VerifyOnce verifies a DPoP proof (see Verify) and additionally enforces
// single use via cache: a proof whose jti has already been seen within the
// acceptance window is rejected with ErrReplayed. The jti is remembered until
// the proof would become stale anyway (iat + MaxAge).
func VerifyOnce(proofJWT, htm, htu string, now time.Time, cache ReplayCache) (*Proof, error) {
	p, err := Verify(proofJWT, htm, htu, now)
	if err != nil {
		return nil, err
	}
	if !cache.CheckAndStore(p.JTI, p.IssuedAt.Add(MaxAge)) {
		return nil, ErrReplayed
	}
	return p, nil
}
