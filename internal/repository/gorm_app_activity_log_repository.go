package repository

import (
	"context"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

type AppActivityLogRepository interface {
	Create(ctx context.Context, log *model.AppActivityLog) error
	FindByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.AppActivityLog, int64, error)
	FindByAppAndCategory(ctx context.Context, appID uint, category model.EventCategory, page, pageSize int) ([]model.AppActivityLog, int64, error)
	FindByDateRange(ctx context.Context, appID uint, start, end time.Time, page, pageSize int) ([]model.AppActivityLog, int64, error)
	CountByEventType(ctx context.Context, appID uint, eventType model.EventType, since time.Time) (int64, error)
}

type appActivityLogRepository struct {
	db *gorm.DB
}

func NewAppActivityLogRepository(db *gorm.DB) AppActivityLogRepository {
	return &appActivityLogRepository{db: db}
}

func (r *appActivityLogRepository) Create(ctx context.Context, log *model.AppActivityLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

func (r *appActivityLogRepository) FindByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.AppActivityLog, int64, error) {
	var logs []model.AppActivityLog
	var totalCount int64

	query := r.db.WithContext(ctx).Model(&model.AppActivityLog{}).Where("app_id = ?", appID)

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Preload("User").
		Where("app_id = ?", appID).
		Offset(offset).
		Limit(pageSize).
		Order("inserted_at DESC").
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}

func (r *appActivityLogRepository) FindByAppAndCategory(ctx context.Context, appID uint, category model.EventCategory, page, pageSize int) ([]model.AppActivityLog, int64, error) {
	var logs []model.AppActivityLog
	var totalCount int64

	query := r.db.WithContext(ctx).Model(&model.AppActivityLog{}).
		Where("app_id = ? AND event_category = ?", appID, category)

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Preload("User").
		Where("app_id = ? AND event_category = ?", appID, category).
		Offset(offset).
		Limit(pageSize).
		Order("inserted_at DESC").
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}

func (r *appActivityLogRepository) FindByDateRange(ctx context.Context, appID uint, start, end time.Time, page, pageSize int) ([]model.AppActivityLog, int64, error) {
	var logs []model.AppActivityLog
	var totalCount int64

	query := r.db.WithContext(ctx).Model(&model.AppActivityLog{}).
		Where("app_id = ? AND inserted_at >= ? AND inserted_at <= ?", appID, start, end)

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Preload("User").
		Where("app_id = ? AND inserted_at >= ? AND inserted_at <= ?", appID, start, end).
		Offset(offset).
		Limit(pageSize).
		Order("inserted_at DESC").
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}

func (r *appActivityLogRepository) CountByEventType(ctx context.Context, appID uint, eventType model.EventType, since time.Time) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.AppActivityLog{}).
		Where("app_id = ? AND event_type = ? AND inserted_at >= ?", appID, eventType, since).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}
