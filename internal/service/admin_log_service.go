package service

import (
	"context"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

type AdminLogService interface {
	LogAction(ctx context.Context, adminID uint, appID *uint, targetUserID *uint, action model.AdminAction, details map[string]interface{}) error
	GetByAdmin(ctx context.Context, adminID uint, page, pageSize int) ([]model.AdminLog, int64, error)
	GetByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.AdminLog, int64, error)
	GetByDateRange(ctx context.Context, appID uint, start, end time.Time, page, pageSize int) ([]model.AdminLog, int64, error)
}

type adminLogService struct {
	repo repository.AdminLogRepository
}

func NewAdminLogService(repo repository.AdminLogRepository) AdminLogService {
	logger.WithFields(logger.Fields{
		"service": "admin_log",
	}).Info("✅ Admin log service initialized")

	return &adminLogService{repo: repo}
}

func (s *adminLogService) LogAction(ctx context.Context, adminID uint, appID *uint, targetUserID *uint, action model.AdminAction, details map[string]interface{}) error {
	log := &model.AdminLog{
		AdminID:      adminID,
		AppID:        appID,
		TargetUserID: targetUserID,
		Action:       action,
		Details:      details,
		CreatedAt:    time.Now(),
	}
	return s.repo.Create(ctx, log)
}

func (s *adminLogService) GetByAdmin(ctx context.Context, adminID uint, page, pageSize int) ([]model.AdminLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.FindByAdmin(ctx, adminID, page, pageSize)
}

func (s *adminLogService) GetByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.AdminLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.FindByApp(ctx, appID, page, pageSize)
}

func (s *adminLogService) GetByDateRange(ctx context.Context, appID uint, start, end time.Time, page, pageSize int) ([]model.AdminLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.FindByDateRange(ctx, appID, start, end, page, pageSize)
}
