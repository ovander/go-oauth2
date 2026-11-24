package repository

import (
	"context"
	"errors"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// ErrTokenAlreadyUsed is returned when a single-use token has already been consumed.
var ErrTokenAlreadyUsed = errors.New("token has already been used")

// UsedTokenRepository defines the interface for used token storage
type UsedTokenRepository interface {
	// MarkAsUsed atomically marks a token as used.
	// Returns ErrTokenAlreadyUsed if the token was already consumed (safe against concurrent calls).
	MarkAsUsed(ctx context.Context, tokenJTI, tokenType string, userID uint, expiresAt time.Time) error
	// IsUsed checks if a token has been used (read-only, not race-safe for enforcement).
	IsUsed(ctx context.Context, tokenJTI string) (bool, error)
	// DeleteExpired removes expired used tokens
	DeleteExpired(ctx context.Context) (int64, error)
}

// UsedTokenTypeReader is implemented by used-token stores that can say how a
// token was used (#365), so a rotated refresh token (a reuse signal) is told
// apart from a revoked one (a logout, or RFC 7009).
type UsedTokenTypeReader interface {
	// UsedTokenType returns the type the token was marked with, or "" when it
	// was not.
	UsedTokenType(ctx context.Context, tokenJTI string) (string, error)
}

type usedTokenRepository struct {
	db *gorm.DB
}

// NewUsedTokenRepository creates a new used token repository
func NewUsedTokenRepository(db *gorm.DB) UsedTokenRepository {
	return &usedTokenRepository{db: db}
}

func (r *usedTokenRepository) MarkAsUsed(ctx context.Context, tokenJTI, tokenType string, userID uint, expiresAt time.Time) error {
	now := time.Now()
	// INSERT ... ON CONFLICT DO NOTHING is atomic: if two concurrent requests
	// race on the same token JTI, the unique index guarantees only one succeeds.
	// RowsAffected == 0 means the row already existed → token was already used.
	result := r.db.WithContext(ctx).Exec(
		`INSERT INTO used_tokens (token_jti, token_type, user_id, used_at, expires_at, inserted_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (token_jti) DO NOTHING`,
		tokenJTI, tokenType, userID, now, expiresAt, now,
	)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrTokenAlreadyUsed
	}
	return nil
}

func (r *usedTokenRepository) IsUsed(ctx context.Context, tokenJTI string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.UsedToken{}).
		Where("token_jti = ?", tokenJTI).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// UsedTokenType implements UsedTokenTypeReader.
func (r *usedTokenRepository) UsedTokenType(ctx context.Context, tokenJTI string) (string, error) {
	var types []string
	if err := r.db.WithContext(ctx).Model(&model.UsedToken{}).
		Where("token_jti = ?", tokenJTI).Limit(1).Pluck("token_type", &types).Error; err != nil {
		return "", err
	}
	if len(types) == 0 {
		return "", nil
	}
	return types[0], nil
}

func (r *usedTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&model.UsedToken{})
	return result.RowsAffected, result.Error
}
