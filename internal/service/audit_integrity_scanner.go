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

		if int64(page*s.pageSize) >= total {
			break
		}
	}

	return checked, violations, nil
}
