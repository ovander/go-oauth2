package repository

import (
	"context"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// UsedTokenRepository defines the interface for used token storage
type UsedTokenRepository interface {
	// MarkAsUsed marks a token as used. Returns error if already used.
	MarkAsUsed(ctx context.Context, tokenJTI, tokenType string, userID uint, expiresAt time.Time) error
	// IsUsed checks if a token has been used
	IsUsed(ctx context.Context, tokenJTI string) (bool, error)
	// DeleteExpired removes expired used tokens
	DeleteExpired(ctx context.Context) (int64, error)
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
	usedToken := &model.UsedToken{
		TokenJTI:  tokenJTI,
		TokenType: tokenType,
		UserID:    userID,
		UsedAt:    now,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	return r.db.WithContext(ctx).Create(usedToken).Error
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

func (r *usedTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&model.UsedToken{})
	return result.RowsAffected, result.Error
}
