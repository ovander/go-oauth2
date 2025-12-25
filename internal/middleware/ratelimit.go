package middleware

import (
	"container/list"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultMaxEntries is the default maximum number of IP entries to track
	DefaultMaxEntries = 10000
)

// RateLimiterConfig holds configuration for the rate limiter
type RateLimiterConfig struct {
	Limit           int
	Window          time.Duration
	MaxEntries      int
	CleanupInterval time.Duration
}

// DefaultRateLimiterConfig returns default configuration
func DefaultRateLimiterConfig(limit int, window time.Duration) RateLimiterConfig {
	return RateLimiterConfig{
		Limit:           limit,
		Window:          window,
		MaxEntries:      DefaultMaxEntries,
		CleanupInterval: time.Minute,
	}
}

// rateLimitEntry holds the request timestamps for an IP
type rateLimitEntry struct {
	key      string
	requests []time.Time
	element  *list.Element
}

// RateLimiter implements an LRU-bounded in-memory rate limiter
type RateLimiter struct {
	requests        map[string]*rateLimitEntry
	lru             *list.List
	mu              sync.RWMutex
	limit           int
	window          time.Duration
	maxEntries      int
	cleanupInterval time.Duration
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// NewRateLimiter creates a new rate limiter with default max entries
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return NewRateLimiterWithConfig(DefaultRateLimiterConfig(limit, window))
}

// NewRateLimiterWithConfig creates a new rate limiter with custom configuration
func NewRateLimiterWithConfig(config RateLimiterConfig) *RateLimiter {
	if config.MaxEntries <= 0 {
		config.MaxEntries = DefaultMaxEntries
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = time.Minute
	}

	rl := &RateLimiter{
		requests:        make(map[string]*rateLimitEntry),
		lru:             list.New(),
		limit:           config.Limit,
		window:          config.Window,
		maxEntries:      config.MaxEntries,
		cleanupInterval: config.CleanupInterval,
		stopCh:          make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.wg.Add(1)
	go rl.cleanup()

	return rl
}

// Allow checks if a request from the given key should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	entry, exists := rl.requests[key]
	if !exists {
		// Check if we need to evict
		if rl.lru.Len() >= rl.maxEntries {
			rl.evictOldest()
		}

		// Create new entry
		entry = &rateLimitEntry{
			key:      key,
			requests: []time.Time{now},
		}
		entry.element = rl.lru.PushFront(entry)
		rl.requests[key] = entry
		return true
	}

	// Move to front (LRU)
	rl.lru.MoveToFront(entry.element)

	// Filter out old requests
	validRequests := make([]time.Time, 0, len(entry.requests))
	for _, t := range entry.requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	// Check if limit exceeded
	if len(validRequests) >= rl.limit {
		entry.requests = validRequests
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	entry.requests = validRequests

	return true
}

// evictOldest removes the oldest (least recently used) entry
func (rl *RateLimiter) evictOldest() {
	oldest := rl.lru.Back()
	if oldest == nil {
		return
	}

	entry := oldest.Value.(*rateLimitEntry)
	rl.lru.Remove(oldest)
	delete(rl.requests, entry.key)
}

// RemainingRequests returns the number of remaining requests for a key
func (rl *RateLimiter) RemainingRequests(key string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	entry, exists := rl.requests[key]
	if !exists {
		return rl.limit
	}

	var count int
	for _, t := range entry.requests {
		if t.After(windowStart) {
			count++
		}
	}

	remaining := rl.limit - count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ResetTime returns when the rate limit will reset for a key
func (rl *RateLimiter) ResetTime(key string) time.Time {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	entry, exists := rl.requests[key]
	if !exists || len(entry.requests) == 0 {
		return time.Now()
	}

	// Find the oldest request in the window
	now := time.Now()
	windowStart := now.Add(-rl.window)

	for _, t := range entry.requests {
		if t.After(windowStart) {
			return t.Add(rl.window)
		}
	}

	return now
}

// Stop gracefully stops the cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
	rl.wg.Wait()
}

// Len returns the current number of tracked IPs
func (rl *RateLimiter) Len() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.requests)
}

// cleanup periodically removes old entries
func (rl *RateLimiter) cleanup() {
	defer rl.wg.Done()

	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			log.Println("Rate limiter cleanup goroutine stopped")
			return
		case <-ticker.C:
			rl.cleanupExpired()
		}
	}
}

// cleanupExpired removes entries with no valid requests in the window
func (rl *RateLimiter) cleanupExpired() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	for key, entry := range rl.requests {
		validRequests := make([]time.Time, 0, len(entry.requests))
		for _, t := range entry.requests {
			if t.After(windowStart) {
				validRequests = append(validRequests, t)
			}
		}
		if len(validRequests) == 0 {
			rl.lru.Remove(entry.element)
			delete(rl.requests, key)
		} else {
			entry.requests = validRequests
		}
	}
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := GetClientIP(r)

			if !limiter.Allow(key) {
				resetTime := limiter.ResetTime(key)
				retryAfter := int(time.Until(resetTime).Seconds())
				if retryAfter < 1 {
					retryAfter = 1
				}

				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limiter.limit))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))

				http.Error(w, `{"error": "too_many_requests", "error_description": "rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			remaining := limiter.RemainingRequests(key)
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limiter.limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

			next.ServeHTTP(w, r)
		})
	}
}

// GetClientIP extracts the client IP from the request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		for i, c := range xff {
			if c == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	return r.RemoteAddr
}
