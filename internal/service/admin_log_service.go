package service

import (
	"context"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/pkg/logger"
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
	}).Debug("✅ Admin log service initialized")

	return &adminLogService{repo: repo}
}

func (s *adminLogService) LogAction(ctx context.Context, adminID uint, appID *uint, targetUserID *uint, action model.AdminAction, details map[string]interface{}) error {
	log := &model.AdminLog{
		AdminID:      adminID,
		AppID:        appID,
		TargetUserID: targetUserID,
		Action:       action,
		Details:      details,
		// RFC-007/RFC-008: tie the admin-action row to the request that
		// produced it. correlationIDFromContext is defined in
		// security_audit_service.go (same package).
		CorrelationID: correlationIDFromContext(ctx),
		CreatedAt:     time.Now(),
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
