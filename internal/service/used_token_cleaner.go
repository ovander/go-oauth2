package service

import (
	"context"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// UsedTokenCleaner periodically prunes expired rows from the used_tokens table
// (EPIC-14 / RFC-012). That table backs two things: single-use refresh-token
// JTI tracking (HIGH-04) and the per-token revocation blacklist (MED-01). Once a
// row's expires_at is in the past the underlying token no longer verifies, so
// the row is dead weight — without pruning the table grows without bound. This
// is the revocation-list hygiene that keeps the freshness machinery cheap.
//
// It depends only on the UsedTokenRepository (DeleteExpired), so it is testable
// without a database.
type UsedTokenCleaner struct {
	repo repository.UsedTokenRepository
}

// NewUsedTokenCleaner builds a cleaner over the given repository.
func NewUsedTokenCleaner(repo repository.UsedTokenRepository) *UsedTokenCleaner {
	return &UsedTokenCleaner{repo: repo}
}

// Cleanup deletes all expired used-token rows and returns how many were removed.
func (c *UsedTokenCleaner) Cleanup(ctx context.Context) (int64, error) {
	if c.repo == nil {
		return 0, nil
	}
	return c.repo.DeleteExpired(ctx)
}

// StartSchedule runs Cleanup every interval and returns a stop function that the
// caller must invoke on shutdown. Each run uses a fresh, bounded background
// context (never tied to a request). stop() closes the schedule and blocks until
// the goroutine has fully exited, giving deterministic shutdown (same contract
// as KeyManager.StartRotationSchedule / AuditIntegrityScanner.StartSchedule).
func (c *UsedTokenCleaner) StartSchedule(interval time.Duration) (stop func()) {
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
				deleted, err := c.Cleanup(ctx)
				cancel()
				switch {
				case err != nil:
					logger.Errorf("EPIC-14: used-token cleanup failed: %v", err)
				case deleted > 0:
					logger.WithFields(logger.Fields{"deleted": deleted}).Info("EPIC-14: pruned expired used tokens")
				}
			case <-stopCh:
				logger.Info("EPIC-14: used-token cleanup schedule stopped")
				return
			}
		}
	}()
	return func() {
		close(stopCh)
		<-doneCh
	}
}
