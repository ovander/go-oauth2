package repository

import (
	"context"
	"time"

	"github.com/socrate-auth/go-oauth/internal/model"
	"gorm.io/gorm"
)

type AdminLogRepository interface {
	Create(ctx context.Context, log *model.AdminLog) error
	FindByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.AdminLog, int64, error)
	FindByAdmin(ctx context.Context, adminID uint, page, pageSize int) ([]model.AdminLog, int64, error)
	FindByDateRange(ctx context.Context, appID uint, start, end time.Time, page, pageSize int) ([]model.AdminLog, int64, error)
}

type adminLogRepository struct {
	db *gorm.DB
}

func NewAdminLogRepository(db *gorm.DB) AdminLogRepository {
	return &adminLogRepository{db: db}
}

func (r *adminLogRepository) Create(ctx context.Context, log *model.AdminLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

func (r *adminLogRepository) FindByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.AdminLog, int64, error) {
	var logs []model.AdminLog
	var totalCount int64

	query := r.db.WithContext(ctx).Model(&model.AdminLog{}).Where("app_id = ?", appID)

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Preload("Admin").
		Preload("TargetUser").
		Where("app_id = ?", appID).
		Offset(offset).
		Limit(pageSize).
		Order("inserted_at DESC").
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}

func (r *adminLogRepository) FindByAdmin(ctx context.Context, adminID uint, page, pageSize int) ([]model.AdminLog, int64, error) {
	var logs []model.AdminLog
	var totalCount int64

	query := r.db.WithContext(ctx).Model(&model.AdminLog{}).Where("admin_id = ?", adminID)

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Preload("App").
		Preload("TargetUser").
		Where("admin_id = ?", adminID).
		Offset(offset).
		Limit(pageSize).
		Order("inserted_at DESC").
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}

func (r *adminLogRepository) FindByDateRange(ctx context.Context, appID uint, start, end time.Time, page, pageSize int) ([]model.AdminLog, int64, error) {
	var logs []model.AdminLog
	var totalCount int64

	query := r.db.WithContext(ctx).Model(&model.AdminLog{}).
		Where("app_id = ? AND inserted_at >= ? AND inserted_at <= ?", appID, start, end)

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Preload("Admin").
		Preload("TargetUser").
		Where("app_id = ? AND inserted_at >= ? AND inserted_at <= ?", appID, start, end).
		Offset(offset).
		Limit(pageSize).
		Order("inserted_at DESC").
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}
