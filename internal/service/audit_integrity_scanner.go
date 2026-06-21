package service

import (
	"context"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

const defaultIntegrityScanPageSize = 500

// AuditIntegrityScanner verifies the per-row HMAC of stored security audit rows
// (RFC-007) and records a critical audit_integrity_violation event for every row
// that fails verification — turning the tamper-evidence stamped at write time
// into actionable detection.
//
// It depends only on the SecurityAuditLogRepository (paging via FindByDateRange,
// writing via Create), so it is testable without a database. The integrity key
// is the same SECRET_KEY_BASE used to stamp the rows; an empty key disables it.
type AuditIntegrityScanner struct {
	repo     repository.SecurityAuditLogRepository
	secret   []byte
	pageSize int
}

// NewAuditIntegrityScanner builds a scanner over the given repository, keyed by
// secret. A nil/empty secret makes Scan a no-op.
func NewAuditIntegrityScanner(repo repository.SecurityAuditLogRepository, secret []byte) *AuditIntegrityScanner {
	return &AuditIntegrityScanner{repo: repo, secret: secret, pageSize: defaultIntegrityScanPageSize}
}

// Scan verifies every audit row created in [since, now] and records a critical
// audit_integrity_violation event (carrying the offending row id) for each
// tampered row. It returns the number of rows checked and violations found, and
// is a no-op (0, 0, nil) when the integrity secret is empty.
//
// The upper bound is captured once at the start, so the violation events Scan
// writes (created after that bound) are not re-scanned within the same run.
func (s *AuditIntegrityScanner) Scan(ctx context.Context, since time.Time) (checked int, violations int, err error) {
	if len(s.secret) == 0 {
		return 0, 0, nil
	}

	end := time.Now()
	for page := 1; ; page++ {
		rows, total, ferr := s.repo.FindByDateRange(ctx, since, end, page, s.pageSize)
		if ferr != nil {
			return checked, violations, ferr
		}
		if len(rows) == 0 {
			break
		}
		checked += len(rows)

		// In-place mutation: a row whose stored HMAC no longer matches.
		for _, id := range repository.VerifyAuditRows(s.secret, rows) {
			violations++
			logger.Errorf("RFC-007: audit integrity violation — security_audit_logs row %d failed HMAC verification", id)
			// Best-effort: record a tamper-evident alert row. Failure to write
			// it must not abort the rest of the scan.
			_ = s.repo.Create(ctx, &model.SecurityAuditLog{
				EventType: model.SecurityEventAuditIntegrityViolation,
				Severity:  model.SecuritySeverityCritical,
				Success:   false,
				Details:   map[string]interface{}{"tampered_row_id": id},
				CreatedAt: time.Now(),
			})
		}

		// Chain break: a row whose backward link does not match its predecessor —
		// what deletion, insertion, or reordering produces.
		for _, id := range repository.VerifyAuditChain(s.secret, rows) {
			violations++
			logger.Errorf("RFC-007: audit chain violation — security_audit_logs row %d has a broken hash-chain link (deletion/reordering)", id)
			_ = s.repo.Create(ctx, &model.SecurityAuditLog{
				EventType: model.SecurityEventAuditIntegrityViolation,
				Severity:  model.SecuritySeverityCritical,
				Success:   false,
				Details:   map[string]interface{}{"chain_break_row_id": id},
				CreatedAt: time.Now(),
			})
		}

		if int64(page*s.pageSize) >= total {
			break
		}
	}

	return checked, violations, nil
}

// StartSchedule runs Scan on the given interval over the trailing lookback
// window, and returns a stop function that the caller must invoke on shutdown.
// A lookback <= 0 falls back to 24h. Each scan uses a fresh, bounded background
// context (it must not be tied to any request). stop() closes the schedule and
// blocks until the goroutine has fully exited (same contract as
// KeyManager.StartRotationSchedule), giving deterministic shutdown.
func (s *AuditIntegrityScanner) StartSchedule(interval, lookback time.Duration) (stop func()) {
	if lookback <= 0 {
		lookback = 24 * time.Hour
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				checked, violations, err := s.Scan(ctx, time.Now().Add(-lookback))
				cancel()
				switch {
				case err != nil:
					logger.Errorf("RFC-007: scheduled audit integrity scan failed: %v", err)
				case violations > 0:
					logger.WithFields(logger.Fields{
						"checked":    checked,
						"violations": violations,
					}).Error("RFC-007: scheduled audit integrity scan found violations")
				default:
					logger.WithFields(logger.Fields{
						"checked": checked,
					}).Info("RFC-007: scheduled audit integrity scan completed (no violations)")
				}
			case <-stopCh:
				logger.Info("RFC-007: audit integrity scan schedule stopped")
				return
			}
		}
	}()
	return func() {
		close(stopCh)
		<-doneCh
	}
}
