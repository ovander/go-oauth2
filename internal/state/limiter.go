package state

import (
	"context"
	"time"

	"github.com/ovander/go-oauth2/pkg/logger"
)

// StoreLimiter adapts a RateLimitStore to the method set the rate-limit
// middleware expects, so the shared and in-process limiters are
// interchangeable at the call site.
type StoreLimiter struct {
	store     RateLimitStore
	namespace string
	limit     int
	window    time.Duration
}

// NewStoreLimiter builds a limiter over a shared store. The namespace keeps the
// login, signup and token limiters in separate key spaces even though they
// share one table.
func NewStoreLimiter(store RateLimitStore, namespace string, limit int, window time.Duration) *StoreLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &StoreLimiter{store: store, namespace: namespace, limit: limit, window: window}
}

// Allow records a request and reports whether it is within the limit.
//
// On a store error it allows the request, logging at error level. Failing open
// looks alarming for a security control, so the reasoning is worth stating: the
// rate limiter protects endpoints that all need this same database to do
// anything useful. If the store is unreachable, login cannot succeed, tokens
// cannot be issued, and there is nothing left for an attacker to brute-force —
// so failing closed would convert a database blip into a self-inflicted outage
// while protecting nothing. The DPoP replay store, whose failure mode really
// would weaken a guarantee, fails closed instead.
func (l *StoreLimiter) Allow(key string) bool {
	count, _, err := l.store.Incr(context.Background(), Key(l.namespace, key), l.window)
	if err != nil {
		logger.WithFields(logger.Fields{
			"error":     err.Error(),
			"namespace": l.namespace,
		}).Error("B4: rate-limit store unavailable — allowing the request (fail open)")
		return true
	}
	return count <= l.limit
}

// RemainingRequests reports how many requests are left in the current window.
func (l *StoreLimiter) RemainingRequests(key string) int {
	count, _, err := l.store.Peek(context.Background(), Key(l.namespace, key), l.window)
	if err != nil {
		return l.limit
	}
	remaining := l.limit - count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ResetTime reports when the current window ends.
func (l *StoreLimiter) ResetTime(key string) time.Time {
	_, reset, err := l.store.Peek(context.Background(), Key(l.namespace, key), l.window)
	if err != nil {
		return time.Now().Add(l.window)
	}
	return reset
}

// Limit returns the configured request limit per window.
func (l *StoreLimiter) Limit() int { return l.limit }

// Stop is a no-op: a shared store has no per-limiter goroutine to wind down.
// It exists so this type is interchangeable with the in-memory limiter.
func (l *StoreLimiter) Stop() {}
