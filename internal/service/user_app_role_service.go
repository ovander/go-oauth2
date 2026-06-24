package service

import (
	"context"
	"errors"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

type UserAppRoleService interface {
	GetUserRoleForApp(ctx context.Context, userID, appID uint) (*model.UserAppRole, error)
	GetUserRoles(ctx context.Context, userID uint) ([]model.UserAppRole, error)
	GetAppUsers(ctx context.Context, appID uint, page, pageSize int, search string) ([]model.UserAppRole, int64, error)
	GetUserRolesMap(ctx context.Context, userID uint) (map[string]string, error)
	AssignRole(ctx context.Context, userID, appID uint, role model.AppRole) (*model.UserAppRole, error)
	UpdateRole(ctx context.Context, userID, appID uint, role model.AppRole) (*model.UserAppRole, error)
	RemoveRole(ctx context.Context, userID, appID uint) error
	SetInviteSent(ctx context.Context, userID, appID uint) error
}

type userAppRoleService struct {
	repo repository.UserAppRoleRepository
}

func NewUserAppRoleService(repo repository.UserAppRoleRepository) UserAppRoleService {
	logger.WithFields(logger.Fields{
		"service": "user_app_role",
	}).Debug("✅ User app role service initialized")

	return &userAppRoleService{repo: repo}
}

func (s *userAppRoleService) GetUserRoleForApp(ctx context.Context, userID, appID uint) (*model.UserAppRole, error) {
	role, err := s.repo.FindByUserAndApp(ctx, userID, appID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return role, nil
}

func (s *userAppRoleService) GetUserRoles(ctx context.Context, userID uint) ([]model.UserAppRole, error) {
	return s.repo.FindByUser(ctx, userID)
}

func (s *userAppRoleService) GetAppUsers(ctx context.Context, appID uint, page, pageSize int, search string) ([]model.UserAppRole, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.FindByApp(ctx, appID, page, pageSize, search)
}

func (s *userAppRoleService) GetUserRolesMap(ctx context.Context, userID uint) (map[string]string, error) {
	return s.repo.GetUserRolesMap(ctx, userID)
}

func (s *userAppRoleService) AssignRole(ctx context.Context, userID, appID uint, role model.AppRole) (*model.UserAppRole, error) {
	// Check if role already exists
	existing, err := s.repo.FindByUserAndApp(ctx, userID, appID)
	if err == nil && existing != nil {
		return nil, ErrRoleAlreadyExists
	}

	userAppRole := &model.UserAppRole{
		UserID:    userID,
		AppID:     appID,
		Role:      role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.repo.Create(ctx, userAppRole); err != nil {
		return nil, err
	}

	return userAppRole, nil
}

func (s *userAppRoleService) UpdateRole(ctx context.Context, userID, appID uint, role model.AppRole) (*model.UserAppRole, error) {
	userAppRole, err := s.GetUserRoleForApp(ctx, userID, appID)
	if err != nil {
		return nil, err
	}

	userAppRole.Role = role
	userAppRole.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, userAppRole); err != nil {
		return nil, err
	}

	return userAppRole, nil
}

func (s *userAppRoleService) RemoveRole(ctx context.Context, userID, appID uint) error {
	_, err := s.GetUserRoleForApp(ctx, userID, appID)
	if err != nil {
		return err
	}

	return s.repo.Delete(ctx, userID, appID)
}

func (s *userAppRoleService) SetInviteSent(ctx context.Context, userID, appID uint) error {
	userAppRole, err := s.GetUserRoleForApp(ctx, userID, appID)
	if err != nil {
		return err
	}

	userAppRole.InviteSent = true
	userAppRole.UpdatedAt = time.Now()

	return s.repo.Update(ctx, userAppRole)
}
