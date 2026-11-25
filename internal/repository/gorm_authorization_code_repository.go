package repository

import (
	"context"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// AuthorizationCodeRepository defines the interface for authorization code storage
type AuthorizationCodeRepository interface {
	Create(ctx context.Context, code *model.AuthorizationCode) error
	FindByCode(ctx context.Context, code string) (*model.AuthorizationCode, error)
	MarkAsUsed(ctx context.Context, code string) error
	Delete(ctx context.Context, code string) error
	DeleteExpired(ctx context.Context) (int64, error)
	DeleteByUserID(ctx context.Context, userID uint) error
}

// AuthorizationCodeRedeemer is implemented by a code repository that records,
// with the redemption itself, the tokens a code is redeemed for.
type AuthorizationCodeRedeemer interface {
	// MarkAsUsedWithTokens marks an unused code used and records the refresh
	// family and access-token jti it is redeemed for, in one statement. A
	// non-zero keepUntil keeps the used code until then (when later than its
	// expiry), so that a replay is still recognised while its tokens live. It
	// returns gorm.ErrRecordNotFound when the code is unknown or already used.
	MarkAsUsedWithTokens(ctx context.Context, code, tokenFamily, accessJTI string, keepUntil time.Time) error
}

// AuthorizationCodeFamilyRetainer is implemented by a code repository that
// can keep the redeemed code of a refresh-token family for longer.
type AuthorizationCodeFamilyRetainer interface {
	// KeepFamilyUntil keeps the used code whose tokens are in tokenFamily
	// until keepUntil, when that is later than its current expiry.
	KeepFamilyUntil(ctx context.Context, tokenFamily string, keepUntil time.Time) error
}

type authorizationCodeRepository struct {
	db *gorm.DB
}

// NewAuthorizationCodeRepository creates a new authorization code repository
func NewAuthorizationCodeRepository(db *gorm.DB) AuthorizationCodeRepository {
	return &authorizationCodeRepository{db: db}
}

func (r *authorizationCodeRepository) Create(ctx context.Context, code *model.AuthorizationCode) error {
	return r.db.WithContext(ctx).Create(code).Error
}

func (r *authorizationCodeRepository) FindByCode(ctx context.Context, code string) (*model.AuthorizationCode, error) {
	var authCode model.AuthorizationCode
	if err := r.db.WithContext(ctx).Where("code = ?", code).First(&authCode).Error; err != nil {
		return nil, err
	}
	return &authCode, nil
}

// MarkAsUsedWithTokens implements AuthorizationCodeRedeemer.
func (r *authorizationCodeRepository) MarkAsUsedWithTokens(ctx context.Context, code, tokenFamily, accessJTI string, keepUntil time.Time) error {
	updates := map[string]interface{}{"used": true, "token_family": tokenFamily, "access_jti": accessJTI}
	if !keepUntil.IsZero() {
		updates["expires_at"] = gorm.Expr("GREATEST(expires_at, ?)", keepUntil)
	}
	result := r.db.WithContext(ctx).Model(&model.AuthorizationCode{}).
		Where("code = ? AND used = ?", code, false).
		Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// KeepFamilyUntil implements AuthorizationCodeFamilyRetainer.
func (r *authorizationCodeRepository) KeepFamilyUntil(ctx context.Context, tokenFamily string, keepUntil time.Time) error {
	if tokenFamily == "" {
		return nil
	}
	return r.db.WithContext(ctx).Model(&model.AuthorizationCode{}).
		Where("token_family = ? AND used = ?", tokenFamily, true).
		Update("expires_at", gorm.Expr("GREATEST(expires_at, ?)", keepUntil)).Error
}

func (r *authorizationCodeRepository) MarkAsUsed(ctx context.Context, code string) error {
	result := r.db.WithContext(ctx).Model(&model.AuthorizationCode{}).
		Where("code = ? AND used = ?", code, false).
		Update("used", true)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (r *authorizationCodeRepository) Delete(ctx context.Context, code string) error {
	return r.db.WithContext(ctx).Where("code = ?", code).Delete(&model.AuthorizationCode{}).Error
}

func (r *authorizationCodeRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&model.AuthorizationCode{})
	return result.RowsAffected, result.Error
}

func (r *authorizationCodeRepository) DeleteByUserID(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&model.AuthorizationCode{}).Error
}
