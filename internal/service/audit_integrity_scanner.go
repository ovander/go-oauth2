package service

import (
	"context"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/pkg/logger"
)

const defaultIntegrityScanPageSize = 500

// AuditIntegrityScanner verifies stored security audit rows (RFC-007) and
// records a critical audit_integrity_violation event for each problem it finds:
// a row failing its HMAC, a broken chain link, a row without a hash after the
// chain started, and a chain head that is missing, invalid or no longer matches
// the row it names (#364).
//
// It reads the rows in id order through an AuditChainReader, carrying the chain
// across pages, and writes the violation events through the
// SecurityAuditLogRepository, so both can be replaced in tests. The integrity
// key is the same SECRET_KEY_BASE used to stamp the rows; an empty key disables
// it.
type AuditIntegrityScanner struct {
	repo     repository.SecurityAuditLogRepository
	chain    repository.AuditChainReader
	secret   []byte
	pageSize int
}

// NewAuditIntegrityScanner builds a scanner reading the chain from chain and
// recording violations through repo, keyed by secret. A nil/empty secret makes
// Scan a no-op.
func NewAuditIntegrityScanner(repo repository.SecurityAuditLogRepository, chain repository.AuditChainReader, secret []byte) *AuditIntegrityScanner {
	return &AuditIntegrityScanner{repo: repo, chain: chain, secret: secret, pageSize: defaultIntegrityScanPageSize}
}

// WithPageSize sets how many rows Scan reads at a time (default 500).
func (s *AuditIntegrityScanner) WithPageSize(n int) *AuditIntegrityScanner {
	if n > 0 {
		s.pageSize = n
	}
	return s
}

// Scan checks the chain head, then verifies every audit row from the first one
// created at or after since up to the newest row when the scan starts, and records
// a critical audit_integrity_violation event for each problem. It returns the
// number of rows checked and violations found, and is a no-op (0, 0, nil) when
// the integrity secret is empty.
//
// The newest row is captured once at the start, so the violation events Scan
// writes are not re-scanned within the same run.
func (s *AuditIntegrityScanner) Scan(ctx context.Context, since time.Time) (checked int, violations int, err error) {
	if len(s.secret) == 0 {
		return 0, 0, nil
	}

	report := func(details map[string]interface{}, format string, args ...interface{}) {
		violations++
		logger.Errorf(format, args...)
		// Best-effort: record a tamper-evident alert row. Failure to write it
		// must not abort the rest of the scan.
		_ = s.repo.Create(ctx, &model.SecurityAuditLog{
			EventType: model.SecurityEventAuditIntegrityViolation,
			Severity:  model.SecuritySeverityCritical,
			Success:   false,
			Details:   details,
			CreatedAt: time.Now(),
		})
	}

	// The newest rows: deleting or blanking them leaves nothing to link-check,
	// but the head still names the row that was there. Read first, before the
	// violation events this scan writes move the head.
	headID, headHash, headProblem, err := s.chain.AuditChainHeadProblem(ctx)
	if err != nil {
		return 0, 0, err
	}
	window, err := s.chain.AuditChainWindow(ctx, since)
	if err != nil {
		return 0, 0, err
	}
	if window.FirstID != 0 {
		walker := repository.NewAuditChainWalker(window.Before, window.Started)
		after := window.FirstID - 1
		for {
			rows, ferr := s.chain.AuditChainRows(ctx, after, window.LastID, s.pageSize)
			if ferr != nil {
				return checked, violations, ferr
			}
			for i := range rows {
				row := &rows[i]
				checked++
				// In-place mutation: a row whose stored HMAC no longer matches.
				if row.RowHash != "" && !repository.VerifyAuditRowHash(s.secret, row) {
					report(map[string]interface{}{"tampered_row_id": row.ID},
						"RFC-007: audit integrity violation — security_audit_logs row %d failed HMAC verification", row.ID)
				}
				switch walker.Next(row) {
				case repository.ChainBreakLink:
					// What deletion, insertion or reordering produces.
					report(map[string]interface{}{"chain_break_row_id": row.ID},
						"RFC-007: audit chain violation — security_audit_logs row %d has a broken hash-chain link (deletion/reordering)", row.ID)
				case repository.ChainBreakUnstamped:
					// What blanking a row's hash produces.
					report(map[string]interface{}{"unstamped_row_id": row.ID},
						"RFC-007: audit chain violation — security_audit_logs row %d has no hash after the chain started", row.ID)
				}
			}
			if len(rows) < s.pageSize {
				break
			}
			after = rows[len(rows)-1].ID
		}
	}

	if headProblem != "" {
		report(map[string]interface{}{"chain_head": headProblem, "head_row_id": headID},
			"RFC-007: audit chain violation — chain head %s (row %d)", headProblem, headID)
	}
	// The head, outside the database: what an attacker who restores an older
	// head and deletes the rows after it cannot change.
	hashPrefix := headHash
	if len(hashPrefix) > 16 {
		hashPrefix = hashPrefix[:16]
	}
	logger.WithFields(logger.Fields{
		"checked":         checked,
		"violations":      violations,
		"chain_head_id":   headID,
		"chain_head_hash": hashPrefix,
	}).Info("RFC-007: audit integrity scan done")

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
