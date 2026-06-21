package repository

import (
	"context"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// MFARecoveryCodeRepository defines storage operations for MFA recovery codes.
type MFARecoveryCodeRepository interface {
	// CreateBatch persists a set of recovery codes (typically in one insert).
	CreateBatch(ctx context.Context, codes []model.MFARecoveryCode) error
	// ListUnusedByUser returns the user's not-yet-redeemed recovery codes.
	ListUnusedByUser(ctx context.Context, userID uint) ([]model.MFARecoveryCode, error)
	// MarkUsed atomically marks a code as consumed. RowsAffected == 0 (already
	// used / not found) is reported via the returned bool.
	MarkUsed(ctx context.Context, id uint) (bool, error)
	// DeleteByUser removes all of a user's recovery codes (used when
	// regenerating a fresh set or disabling MFA).
	DeleteByUser(ctx context.Context, userID uint) error
	// CountUnusedByUser counts the user's remaining unused codes.
	CountUnusedByUser(ctx context.Context, userID uint) (int64, error)
}

type mfaRecoveryCodeRepository struct {
	db *gorm.DB
}

// NewMFARecoveryCodeRepository creates a GORM-backed MFARecoveryCodeRepository.
func NewMFARecoveryCodeRepository(db *gorm.DB) MFARecoveryCodeRepository {
	return &mfaRecoveryCodeRepository{db: db}
}

func (r *mfaRecoveryCodeRepository) CreateBatch(ctx context.Context, codes []model.MFARecoveryCode) error {
	if len(codes) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Create(&codes).Error
}

func (r *mfaRecoveryCodeRepository) ListUnusedByUser(ctx context.Context, userID uint) ([]model.MFARecoveryCode, error) {
	var codes []model.MFARecoveryCode
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND used_at IS NULL", userID).
		Find(&codes).Error
	if err != nil {
		return nil, err
	}
	return codes, nil
}

func (r *mfaRecoveryCodeRepository) MarkUsed(ctx context.Context, id uint) (bool, error) {
	res := r.db.WithContext(ctx).
		Model(&model.MFARecoveryCode{}).
		Where("id = ? AND used_at IS NULL", id).
		Update("used_at", gorm.Expr("NOW()"))
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (r *mfaRecoveryCodeRepository) DeleteByUser(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&model.MFARecoveryCode{}).Error
}

func (r *mfaRecoveryCodeRepository) CountUnusedByUser(ctx context.Context, userID uint) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).
		Model(&model.MFARecoveryCode{}).
		Where("user_id = ? AND used_at IS NULL", userID).
		Count(&n).Error
	return n, err
}
