package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gorm.io/gorm"
)

// LoginSourceFailureRepository counts failed sign-ins per account and source
// (#403, LOCKOUT_SOURCE_MODE): a burst of wrong passwords from one source locks
// that source out of that account, not the owner everywhere. The source is a
// client address or prefix; the table is login_source_failures (migration 0034).
type LoginSourceFailureRepository interface {
	// RecordFailure counts one failure of userID from source and returns the
	// count. Failures older than window are forgotten: a count whose last
	// failure is older starts again at 1.
	RecordFailure(ctx context.Context, userID uint, source string, window time.Duration) (int, error)
	// Lock locks source out of userID's account until the given time and
	// starts its count again.
	Lock(ctx context.Context, userID uint, source string, until time.Time) error
	// LockedUntil returns when the lock of source on userID ends, or nil when
	// there is none in force.
	LockedUntil(ctx context.Context, userID uint, source string) (*time.Time, error)
	// Reset forgets the failures of source on userID (a complete sign-in).
	Reset(ctx context.Context, userID uint, source string) error
	// DeleteStale removes the rows whose last failure is before the given
	// time and that hold no lock still in force.
	DeleteStale(ctx context.Context, before time.Time) (int64, error)
}

type loginSourceFailureRepository struct {
	db *gorm.DB
}

// NewLoginSourceFailureRepository returns the PostgreSQL store.
func NewLoginSourceFailureRepository(db *gorm.DB) LoginSourceFailureRepository {
	return &loginSourceFailureRepository{db: db}
}

func (r *loginSourceFailureRepository) RecordFailure(ctx context.Context, userID uint, source string, window time.Duration) (int, error) {
	now := time.Now().UTC()
	var count int
	err := r.db.WithContext(ctx).Raw(`
		INSERT INTO login_source_failures (user_id, source, failed_attempts, updated_at)
		VALUES (?, ?, 1, ?)
		ON CONFLICT (user_id, source) DO UPDATE SET
			failed_attempts = CASE WHEN login_source_failures.updated_at < ?
				THEN 1 ELSE login_source_failures.failed_attempts + 1 END,
			updated_at = EXCLUDED.updated_at
		RETURNING failed_attempts`,
		userID, source, now, now.Add(-window)).Scan(&count).Error
	return count, err
}

func (r *loginSourceFailureRepository) Lock(ctx context.Context, userID uint, source string, until time.Time) error {
	now := time.Now().UTC()
	return r.db.WithContext(ctx).Exec(`
		INSERT INTO login_source_failures (user_id, source, failed_attempts, locked_until, updated_at)
		VALUES (?, ?, 0, ?, ?)
		ON CONFLICT (user_id, source) DO UPDATE SET
			failed_attempts = 0, locked_until = EXCLUDED.locked_until, updated_at = EXCLUDED.updated_at`,
		userID, source, until.UTC(), now).Error
}

func (r *loginSourceFailureRepository) LockedUntil(ctx context.Context, userID uint, source string) (*time.Time, error) {
	var until sql.NullTime
	err := r.db.WithContext(ctx).Raw(`
		SELECT locked_until FROM login_source_failures
		WHERE user_id = ? AND source = ? AND locked_until > ?`,
		userID, source, time.Now().UTC()).Row().Scan(&until)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !until.Valid) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &until.Time, nil
}

func (r *loginSourceFailureRepository) Reset(ctx context.Context, userID uint, source string) error {
	return r.db.WithContext(ctx).Exec(
		`DELETE FROM login_source_failures WHERE user_id = ? AND source = ?`, userID, source).Error
}

func (r *loginSourceFailureRepository) DeleteStale(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).Exec(`
		DELETE FROM login_source_failures
		WHERE updated_at < ? AND (locked_until IS NULL OR locked_until < ?)`,
		before.UTC(), time.Now().UTC())
	return res.RowsAffected, res.Error
}
