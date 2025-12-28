package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// IPBlockChecker provides IP blocking functionality with caching
type IPBlockChecker struct {
	repo        repository.BlockedIPRepository
	cache       map[string]cacheEntry
	mu          sync.RWMutex
	cacheTTL    time.Duration
	stopCh      chan struct{}
	wg          sync.WaitGroup
	refreshChan chan struct{}
}

type cacheEntry struct {
	blocked   bool
	expiresAt time.Time
}

// IPBlockCheckerConfig holds configuration for the IP block checker
type IPBlockCheckerConfig struct {
	CacheTTL        time.Duration // How long to cache block status
	RefreshInterval time.Duration // How often to refresh from database
}

// DefaultIPBlockCheckerConfig returns sensible defaults
func DefaultIPBlockCheckerConfig() IPBlockCheckerConfig {
	return IPBlockCheckerConfig{
		CacheTTL:        30 * time.Second,  // Cache for 30 seconds
		RefreshInterval: 60 * time.Second,  // Refresh from DB every minute
	}
}

// NewIPBlockChecker creates a new IP block checker with caching
func NewIPBlockChecker(repo repository.BlockedIPRepository, config IPBlockCheckerConfig) *IPBlockChecker {
	if config.CacheTTL == 0 {
		config.CacheTTL = 30 * time.Second
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 60 * time.Second
	}

	checker := &IPBlockChecker{
		repo:        repo,
		cache:       make(map[string]cacheEntry),
		cacheTTL:    config.CacheTTL,
		stopCh:      make(chan struct{}),
		refreshChan: make(chan struct{}, 1),
	}

	// Start background refresh goroutine
	checker.wg.Add(1)
	go checker.backgroundRefresh(config.RefreshInterval)

	// Initial load
	checker.refreshCache()

	return checker
}

// IsBlocked checks if an IP is blocked (uses cache for performance)
func (c *IPBlockChecker) IsBlocked(ctx context.Context, ip string) bool {
	c.mu.RLock()
	entry, exists := c.cache[ip]
	c.mu.RUnlock()

	if exists && time.Now().Before(entry.expiresAt) {
		return entry.blocked
	}

	// Cache miss or expired - check database
	blocked, err := c.repo.IsBlocked(ctx, ip)
	if err != nil {
		logger.Errorf("Failed to check IP block status: %v", err)
		// On error, check if we have stale cache data
		if exists {
			return entry.blocked
		}
		return false // Fail open on errors
	}

	// Update cache
	c.mu.Lock()
	c.cache[ip] = cacheEntry{
		blocked:   blocked,
		expiresAt: time.Now().Add(c.cacheTTL),
	}
	c.mu.Unlock()

	return blocked
}

// InvalidateCache triggers an immediate cache refresh
func (c *IPBlockChecker) InvalidateCache() {
	select {
	case c.refreshChan <- struct{}{}:
	default:
		// Refresh already pending
	}
}

// Stop gracefully stops the background refresh goroutine
func (c *IPBlockChecker) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

func (c *IPBlockChecker) backgroundRefresh(interval time.Duration) {
	defer c.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			logger.Info("IP block checker stopped")
			return
		case <-ticker.C:
			c.refreshCache()
		case <-c.refreshChan:
			c.refreshCache()
		}
	}
}

func (c *IPBlockChecker) refreshCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	blockedIPs, err := c.repo.FindActive(ctx)
	if err != nil {
		logger.Errorf("Failed to refresh blocked IP cache: %v", err)
		return
	}

	c.mu.Lock()
	// Clear and rebuild cache
	c.cache = make(map[string]cacheEntry)
	now := time.Now()
	for _, ip := range blockedIPs {
		c.cache[ip.IPAddress] = cacheEntry{
			blocked:   true,
			expiresAt: now.Add(c.cacheTTL),
		}
	}
	c.mu.Unlock()

	logger.Debugf("Refreshed IP block cache: %d blocked IPs", len(blockedIPs))
}

// IPBlockMiddleware creates middleware that blocks requests from blocked IPs
func IPBlockMiddleware(checker *IPBlockChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := GetClientIP(r)

			if checker.IsBlocked(r.Context(), ip) {
				logger.Warnf("Blocked request from banned IP: %s", ip)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error": "access_denied", "error_description": "your IP address has been blocked"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
