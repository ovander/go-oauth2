package middleware

import (
	"container/list"
	"fmt"
	"github.com/ovander/go-oauth2/internal/metrics"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ovander/go-oauth2/pkg/logger"
)

const (
	// DefaultMaxEntries is the default maximum number of IP entries to track
	DefaultMaxEntries = 10000
)

// Limiter is the rate-limiting behaviour the middleware depends on. The
// in-process RateLimiter below and the shared-store limiter in internal/state
// (B4) both satisfy it, so which backend is in use is a bootstrap decision the
// middleware never sees.
type Limiter interface {
	// Allow records a request for key and reports whether it is within the limit.
	Allow(key string) bool
	// RemainingRequests reports how many requests remain in the current window.
	RemainingRequests(key string) int
	// ResetTime reports when the current window ends.
	ResetTime(key string) time.Time
	// Limit is the configured number of requests per window.
	Limit() int
	// Stop releases any background resources.
	Stop()
}

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

// Limit returns the configured number of requests allowed per window.
func (rl *RateLimiter) Limit() int { return rl.limit }

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
			// L-02 fix: use the project's structured logrus logger instead of
			// the stdlib log package so shutdown messages appear in the same
			// format and destination as all other application log output.
			logger.Info("Rate limiter cleanup goroutine stopped")
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

// RateLimitMiddleware creates a rate-limiting middleware.
// trustedCIDRs controls which upstream proxies may supply X-Forwarded-For /
// X-Real-IP headers.  Pass nil (or an empty slice) to always use RemoteAddr
// directly and never trust proxy headers — the safe default.
func RateLimitMiddleware(limiter Limiter, trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := GetClientIPSafe(r, trustedCIDRs)

			if !limiter.Allow(key) {
				metrics.RateLimited(r)
				resetTime := limiter.ResetTime(key)
				retryAfter := int(time.Until(resetTime).Seconds())
				if retryAfter < 1 {
					retryAfter = 1
				}

				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limiter.Limit()))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))

				http.Error(w, `{"error": "too_many_requests", "error_description": "rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			remaining := limiter.RemainingRequests(key)
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limiter.Limit()))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

			next.ServeHTTP(w, r)
		})
	}
}

// GetClientIPSafe extracts the real client IP in a spoofing-resistant way.
//
// Proxy headers (X-Forwarded-For, X-Real-IP) are trusted ONLY when the
// immediate TCP connection (RemoteAddr) comes from one of the supplied
// trustedCIDRs.  If trustedCIDRs is nil or empty the function always returns
// the bare RemoteAddr, making it safe even when the server is exposed directly
// to the internet.
func GetClientIPSafe(r *http.Request, trustedCIDRs []*net.IPNet) string {
	remoteIP := extractRemoteIP(r.RemoteAddr)

	if len(trustedCIDRs) > 0 && isIPInCIDRs(remoteIP, trustedCIDRs) {
		// Connection comes from a trusted proxy — honour its forwarding headers.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// XFF is a comma-separated list; the leftmost entry is the original client.
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	return remoteIP
}

// extractRemoteIP strips the port from a "host:port" address.
func extractRemoteIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// isIPInCIDRs reports whether ipStr falls within any of the supplied CIDRs.
func isIPInCIDRs(ipStr string, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxyCIDRs parses a comma-separated list of IPs / CIDR blocks
// into []*net.IPNet.  Plain IPs are treated as /32 (IPv4) or /128 (IPv6).
// An empty value or the literal "none" (case-insensitive) yields nil — no
// proxy is trusted and RemoteAddr is always used as-is.
func ParseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "none") {
		return nil, nil
	}
	var cidrs []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Normalise bare IPs to CIDR notation.
		if !strings.Contains(entry, "/") {
			if strings.Contains(entry, ":") {
				entry += "/128" // IPv6
			} else {
				entry += "/32" // IPv4
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", entry, err)
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs, nil
}
