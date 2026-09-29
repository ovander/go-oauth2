package service

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// AutoDefenseConfig configures automatic defense thresholds
type AutoDefenseConfig struct {
	// Login failure thresholds
	FailedLoginThreshold      int           // Block after this many failures
	FailedLoginWindow         time.Duration // Within this time window
	InitialBlockDuration      time.Duration // First block duration
	MaxBlockDuration          time.Duration // Maximum block duration (escalates)
	BlockEscalationMultiplier float64       // Multiply block duration on repeated offenses

	// Brute force detection
	BruteForceThreshold int           // Rapid failures indicating brute force
	BruteForceWindow    time.Duration // Very short window for brute force

	// Cleanup settings
	CleanupInterval time.Duration
	MaxTrackedIPs   int
}

// DefaultAutoDefenseConfig returns sensible defaults
func DefaultAutoDefenseConfig() AutoDefenseConfig {
	return AutoDefenseConfig{
		FailedLoginThreshold:      10,               // 10 failures
		FailedLoginWindow:         10 * time.Minute, // in 10 minutes
		InitialBlockDuration:      15 * time.Minute, // 15 min initial block
		MaxBlockDuration:          24 * time.Hour,   // Up to 24 hours
		BlockEscalationMultiplier: 2.0,              // Double on each offense

		BruteForceThreshold: 20,               // 20 attempts
		BruteForceWindow:    30 * time.Second, // in 30 seconds = brute force

		CleanupInterval: 5 * time.Minute,
		MaxTrackedIPs:   50000,
	}
}

// ipRecord tracks activity for a single IP
type ipRecord struct {
	IP             string
	FailedAttempts []time.Time
	BlockCount     int // Number of times this IP has been blocked
	LastActivity   time.Time
	// element is the record's position in the LRU list so evictOldest can
	// remove it in O(1) instead of scanning all tracked IPs (L-03 fix).
	element *list.Element
}

// AutoDefenseService provides automatic threat detection and blocking
type AutoDefenseService struct {
	config            AutoDefenseConfig
	blockedIPRepo     repository.BlockedIPRepository
	securityAuditRepo repository.SecurityAuditLogRepository

	// In-memory tracking for real-time detection
	ipRecords map[string]*ipRecord
	// lru keeps ipRecord pointers ordered by last activity so evictOldest
	// is O(1) rather than O(n) — L-03 fix.
	lru *list.List
	mu  sync.RWMutex

	// Background processing
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Callback to notify other components (e.g., invalidate IP block cache)
	onBlock func(ip string)
}

// NewAutoDefenseService creates a new automatic defense service
func NewAutoDefenseService(
	blockedIPRepo repository.BlockedIPRepository,
	securityAuditRepo repository.SecurityAuditLogRepository,
	config AutoDefenseConfig,
) *AutoDefenseService {
	if config.FailedLoginThreshold == 0 {
		config = DefaultAutoDefenseConfig()
	}

	svc := &AutoDefenseService{
		config:            config,
		blockedIPRepo:     blockedIPRepo,
		securityAuditRepo: securityAuditRepo,
		ipRecords:         make(map[string]*ipRecord),
		lru:               list.New(),
		stopCh:            make(chan struct{}),
	}

	// Start background cleanup
	svc.wg.Add(1)
	go svc.cleanup()

	return svc
}

// SetOnBlockCallback sets a callback to be called when an IP is blocked
func (s *AutoDefenseService) SetOnBlockCallback(callback func(ip string)) {
	s.onBlock = callback
}

// RecordFailedLogin records a failed login attempt and checks if IP should be blocked
func (s *AutoDefenseService) RecordFailedLogin(ctx context.Context, ip string, userAgent string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Get or create record
	record, exists := s.ipRecords[ip]
	if !exists {
		// LRU eviction if needed
		if len(s.ipRecords) >= s.config.MaxTrackedIPs {
			s.evictOldest()
		}
		record = &ipRecord{
			IP:             ip,
			FailedAttempts: make([]time.Time, 0, s.config.FailedLoginThreshold),
		}
		// Push to LRU front so new IPs are considered most-recently-used.
		record.element = s.lru.PushFront(record)
		s.ipRecords[ip] = record
	} else {
		// Move to front on activity — keeps the LRU ordering accurate.
		s.lru.MoveToFront(record.element)
	}

	record.FailedAttempts = append(record.FailedAttempts, now)
	record.LastActivity = now

	// Check for brute force (rapid failures)
	bruteForceWindow := now.Add(-s.config.BruteForceWindow)
	bruteForceCount := 0
	for _, t := range record.FailedAttempts {
		if t.After(bruteForceWindow) {
			bruteForceCount++
		}
	}

	if bruteForceCount >= s.config.BruteForceThreshold {
		s.blockIPUnlocked(ctx, ip, "brute_force_attack", record, true)
		return
	}

	// Check for standard threshold breach
	loginWindow := now.Add(-s.config.FailedLoginWindow)
	failureCount := 0
	for _, t := range record.FailedAttempts {
		if t.After(loginWindow) {
			failureCount++
		}
	}

	if failureCount >= s.config.FailedLoginThreshold {
		s.blockIPUnlocked(ctx, ip, "failed_login_threshold", record, false)
	}
}

// blockIPUnlocked blocks an IP (caller must hold lock)
func (s *AutoDefenseService) blockIPUnlocked(ctx context.Context, ip, reason string, record *ipRecord, isBruteForce bool) {
	// Calculate block duration with escalation
	blockDuration := s.config.InitialBlockDuration
	for i := 0; i < record.BlockCount; i++ {
		blockDuration = time.Duration(float64(blockDuration) * s.config.BlockEscalationMultiplier)
		if blockDuration > s.config.MaxBlockDuration {
			blockDuration = s.config.MaxBlockDuration
			break
		}
	}

	// For brute force, use longer initial duration
	if isBruteForce && blockDuration < time.Hour {
		blockDuration = time.Hour
	}

	expiresAt := time.Now().Add(blockDuration)

	blockedIP := &model.BlockedIP{
		IPAddress: ip,
		Reason:    fmt.Sprintf("Automatic block: %s (offense #%d)", reason, record.BlockCount+1),
		ExpiresAt: &expiresAt,
		Permanent: false,
		BlockedAt: time.Now(),
	}

	// Use background context for database operation since this may be triggered
	// in various request contexts
	bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.blockedIPRepo.Create(bgCtx, blockedIP); err != nil {
		logger.Errorf("Failed to auto-block IP %s: %v", ip, err)
		return
	}

	record.BlockCount++
	record.FailedAttempts = nil // Reset failed attempts after blocking

	logger.Warnf("AUTO-DEFENSE: Blocked IP %s for %v (reason: %s, offense #%d)",
		ip, blockDuration, reason, record.BlockCount)

	// Log security event
	if s.securityAuditRepo != nil {
		auditLog := &model.SecurityAuditLog{
			EventType: model.SecurityEventType("auto_ip_block"),
			Severity:  model.SecuritySeverityCritical,
			IPAddress: ip,
			Success:   true,
			Details: map[string]interface{}{
				"reason":         reason,
				"offense_count":  record.BlockCount,
				"duration_secs":  int(blockDuration.Seconds()),
				"expires_at":     expiresAt.Format(time.RFC3339),
				"is_brute_force": isBruteForce,
			},
		}
		if err := s.securityAuditRepo.Create(bgCtx, auditLog); err != nil {
			logger.Warnf("autoDefense: failed to persist security audit log for IP block (%s): %v", ip, err)
		}
	}

	// Notify callback
	if s.onBlock != nil {
		go s.onBlock(ip)
	}
}

// RecordSuccessfulLogin clears failed attempt tracking for an IP
func (s *AutoDefenseService) RecordSuccessfulLogin(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record, exists := s.ipRecords[ip]; exists {
		record.FailedAttempts = nil
		record.LastActivity = time.Now()
	}
}

// evictOldest removes the least-recently-used IP record.
//
// L-03 fix: the previous implementation iterated all tracked IPs in O(n) to
// find the one with the oldest LastActivity timestamp.  By maintaining a
// doubly-linked LRU list we can find and remove the tail in O(1).
func (s *AutoDefenseService) evictOldest() {
	oldest := s.lru.Back()
	if oldest == nil {
		return
	}
	record := oldest.Value.(*ipRecord)
	s.lru.Remove(oldest)
	delete(s.ipRecords, record.IP)
}

// cleanup periodically cleans up old records
func (s *AutoDefenseService) cleanup() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			logger.Info("Auto-defense service stopped")
			return
		case <-ticker.C:
			s.cleanupExpired()
		}
	}
}

func (s *AutoDefenseService) cleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expireBefore := now.Add(-s.config.FailedLoginWindow * 2) // Keep records a bit longer

	for ip, record := range s.ipRecords {
		// Remove records with no recent activity and no failed attempts
		if record.LastActivity.Before(expireBefore) && len(record.FailedAttempts) == 0 {
			s.lru.Remove(record.element)
			delete(s.ipRecords, ip)
			continue
		}

		// Clean up old failed attempts
		if len(record.FailedAttempts) > 0 {
			validAttempts := make([]time.Time, 0, len(record.FailedAttempts))
			windowStart := now.Add(-s.config.FailedLoginWindow)
			for _, t := range record.FailedAttempts {
				if t.After(windowStart) {
					validAttempts = append(validAttempts, t)
				}
			}
			record.FailedAttempts = validAttempts
		}
	}

	// Also cleanup expired blocked IPs from database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cleaned, err := s.blockedIPRepo.CleanupExpired(ctx)
	if err != nil {
		logger.Errorf("Failed to cleanup expired blocked IPs: %v", err)
	} else if cleaned > 0 {
		logger.Infof("Cleaned up %d expired blocked IPs", cleaned)
	}
}

// Stop gracefully stops the auto-defense service
func (s *AutoDefenseService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// GetStats returns current auto-defense statistics
func (s *AutoDefenseService) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Count IPs with recent activity
	now := time.Now()
	activeWindow := now.Add(-s.config.FailedLoginWindow)
	activeIPs := 0
	highRiskIPs := 0

	for _, record := range s.ipRecords {
		if record.LastActivity.After(activeWindow) {
			activeIPs++
			if len(record.FailedAttempts) >= s.config.FailedLoginThreshold/2 {
				highRiskIPs++
			}
		}
	}

	return map[string]interface{}{
		"tracked_ips":   len(s.ipRecords),
		"active_ips":    activeIPs,
		"high_risk_ips": highRiskIPs,
		"config": map[string]interface{}{
			"failed_login_threshold": s.config.FailedLoginThreshold,
			"failed_login_window":    s.config.FailedLoginWindow.String(),
			"brute_force_threshold":  s.config.BruteForceThreshold,
			"brute_force_window":     s.config.BruteForceWindow.String(),
			"initial_block_duration": s.config.InitialBlockDuration.String(),
			"max_block_duration":     s.config.MaxBlockDuration.String(),
		},
	}
}
