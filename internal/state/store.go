// Package state holds the shared-state adapters that let Socrate run as more
// than one instance (B4 / EPIC-13).
//
// Several controls keep their state in the process: the rate limiters, the DPoP
// replay cache, auto-defense's per-IP counters. On one instance that is correct
// and fast. On N instances behind a load balancer each holds its own copy, and
// the controls quietly weaken:
//
//   - a rate limit of 5/min becomes 5N/min, because each instance counts only
//     the requests it happened to receive;
//   - a DPoP proof replayed against a *different* instance is accepted, because
//     the instance that saw it first is the only one that remembers the jti.
//
// The second is a security hole, not a performance wrinkle. This package makes
// the state shareable behind interfaces, with memory as the default and
// Postgres as the first shared backend — no new infrastructure, since the
// database is already there.
package state

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Backend names the store implementation (STATE_BACKEND).
const (
	// BackendMemory keeps state in the process. Correct for a single instance,
	// and the default so nothing changes for existing deployments.
	BackendMemory = "memory"
	// BackendPostgres shares state through the database Socrate already uses.
	BackendPostgres = "postgres"
)

// NormalizeBackend lower-cases and validates a configured backend, falling back
// to memory for anything unrecognized — a typo must not silently change where
// security state lives.
func NormalizeBackend(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case BackendPostgres:
		return BackendPostgres
	default:
		return BackendMemory
	}
}

// RateLimitStore is a fixed-window counter keyed by an opaque string.
//
// Fixed windows, not the sliding window the in-memory limiter uses: a sliding
// window needs per-request timestamps, which is a row per request in a shared
// store. The tradeoff is the well-known one — a caller can send `limit`
// requests at the end of one window and `limit` more at the start of the next,
// so the true worst case is 2×limit across a window boundary. For brute-force
// resistance at these limits that is acceptable, and it is documented rather
// than glossed over.
type RateLimitStore interface {
	// Incr counts one request against key and returns the resulting count
	// within the current window, plus when that window ends.
	Incr(ctx context.Context, key string, window time.Duration) (count int, resetAt time.Time, err error)
	// Peek returns the current count without recording a request.
	Peek(ctx context.Context, key string, window time.Duration) (count int, resetAt time.Time, err error)
	// Sweep removes expired rows and returns how many it deleted.
	Sweep(ctx context.Context) (int64, error)
}

// ReplayStore records single-use identifiers (DPoP jti) until they expire. It
// satisfies dpop.ReplayCache structurally, so the dpop package needs no
// knowledge of this one.
type ReplayStore interface {
	// CheckAndStore records id when it is not already present and unexpired,
	// returning true. A live entry means a replay and returns false.
	CheckAndStore(id string, exp time.Time) bool
	// Sweep removes expired rows and returns how many it deleted.
	Sweep(ctx context.Context) (int64, error)
}

// windowStart truncates now to the start of its fixed window. Truncation is on
// the absolute clock, so every instance computes the same boundary for the same
// window size without any coordination.
func windowStart(now time.Time, window time.Duration) time.Time {
	if window <= 0 {
		window = time.Minute
	}
	return now.UTC().Truncate(window)
}

// Key builds a namespaced store key, so counters for different controls cannot
// collide in the shared table.
func Key(namespace, id string) string {
	return fmt.Sprintf("%s:%s", namespace, id)
}
