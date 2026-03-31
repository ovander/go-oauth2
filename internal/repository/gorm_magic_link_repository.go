package repository

import (
	"context"
	"errors"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// Sentinel errors returned by MagicLinkRepository.
var (
	ErrMagicLinkNotFound    = errors.New("magic link token not found")
	ErrMagicLinkAlreadyUsed = errors.New("magic link token has already been used")
)

// MagicLinkRepository defines storage operations for magic-link tokens.
type MagicLinkRepository interface {
	// Create persists a new magic-link token.
	Create(ctx context.Context, token *model.MagicLinkToken) error
	// FindByTokenHash looks up a token by its SHA-256 hex digest.
	FindByTokenHash(ctx context.Context, hash string) (*model.MagicLinkToken, error)
	// MarkUsed atomically marks a token as consumed.
	// Returns ErrMagicLinkAlreadyUsed if RowsAffected == 0 (concurrent race).
	MarkUsed(ctx context.Context, id uint) error
	// CountUnusedByEmail counts unused tokens created after `since` for the
	// given (email, appID) pair.  Used for per-address rate limiting.
	CountUnusedByEmail(ctx context.Context, email string, appID uint, since time.Time) (int64, error)
	// DeleteExpired purges tokens whose ExpiresAt is in the past.
	DeleteExpired(ctx context.Context) (int64, error)
}

type magicLinkRepository struct {
	db *gorm.DB
}

// NewMagicLinkRepository creates a new GORM-backed MagicLinkRepository.
func NewMagicLinkRepository(db *gorm.DB) MagicLinkRepository {
	return &magicLinkRepository{db: db}
}

func (r *magicLinkRepository) Create(ctx context.Context, token *model.MagicLinkToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *magicLinkRepository) FindByTokenHash(ctx context.Context, hash string) (*model.MagicLinkToken, error) {
	var token model.MagicLinkToken
	err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrMagicLinkNotFound
	}
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *magicLinkRepository) MarkUsed(ctx context.Context, id uint) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&model.MagicLinkToken{}).
		Where("id = ? AND used = false", id).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrMagicLinkAlreadyUsed
	}
	return nil
}

func (r *magicLinkRepository) CountUnusedByEmail(ctx context.Context, email string, appID uint, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.MagicLinkToken{}).
		Where("email = ? AND app_id = ? AND used = false AND inserted_at >= ?", email, appID, since).
		Count(&count).Error
	return count, err
}

func (r *magicLinkRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&model.MagicLinkToken{})
	return result.RowsAffected, result.Error
}
