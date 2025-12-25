package service

import (
	"context"
	"time"

	"github.com/socrate-auth/go-oauth/internal/model"
	"github.com/socrate-auth/go-oauth/internal/repository"
)

type AppActivityLogService interface {
	LogEvent(ctx context.Context, appID uint, userID *uint, eventType model.EventType, category model.EventCategory, metadata map[string]interface{}, ipAddress, userAgent string, success bool) error
	GetByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.AppActivityLog, int64, error)
	GetByCategory(ctx context.Context, appID uint, category model.EventCategory, page, pageSize int) ([]model.AppActivityLog, int64, error)
	GetByDateRange(ctx context.Context, appID uint, start, end time.Time, page, pageSize int) ([]model.AppActivityLog, int64, error)
	CountByEventType(ctx context.Context, appID uint, eventType model.EventType, since time.Time) (int64, error)
}

type appActivityLogService struct {
	repo repository.AppActivityLogRepository
}

func NewAppActivityLogService(repo repository.AppActivityLogRepository) AppActivityLogService {
	return &appActivityLogService{repo: repo}
}

func (s *appActivityLogService) LogEvent(ctx context.Context, appID uint, userID *uint, eventType model.EventType, category model.EventCategory, metadata map[string]interface{}, ipAddress, userAgent string, success bool) error {
	var ip, ua *string
	if ipAddress != "" {
		ip = &ipAddress
	}
	if userAgent != "" {
		ua = &userAgent
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	log := &model.AppActivityLog{
		AppID:         appID,
		UserID:        userID,
		EventType:     eventType,
		EventCategory: category,
		Metadata:      metadata,
		IPAddress:     ip,
		UserAgent:     ua,
		Success:       success,
		CreatedAt:     time.Now(),
	}
	return s.repo.Create(ctx, log)
}

func (s *appActivityLogService) GetByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.AppActivityLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.FindByApp(ctx, appID, page, pageSize)
}

func (s *appActivityLogService) GetByCategory(ctx context.Context, appID uint, category model.EventCategory, page, pageSize int) ([]model.AppActivityLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.FindByAppAndCategory(ctx, appID, category, page, pageSize)
}

func (s *appActivityLogService) GetByDateRange(ctx context.Context, appID uint, start, end time.Time, page, pageSize int) ([]model.AppActivityLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.FindByDateRange(ctx, appID, start, end, page, pageSize)
}

func (s *appActivityLogService) CountByEventType(ctx context.Context, appID uint, eventType model.EventType, since time.Time) (int64, error) {
	return s.repo.CountByEventType(ctx, appID, eventType, since)
}
