package repository

import (
	"context"
	"time"

	"github.com/socrate-auth/go-oauth/internal/model"
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
