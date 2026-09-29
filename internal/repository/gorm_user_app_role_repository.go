package repository

import (
	"context"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

type UserAppRoleRepository interface {
	FindByUserAndApp(ctx context.Context, userID, appID uint) (*model.UserAppRole, error)
	FindByUser(ctx context.Context, userID uint) ([]model.UserAppRole, error)
	FindByApp(ctx context.Context, appID uint, page, pageSize int, search string) ([]model.UserAppRole, int64, error)
	FindAllByUser(ctx context.Context, userID uint) ([]model.UserAppRole, error)
	Create(ctx context.Context, role *model.UserAppRole) error
	Update(ctx context.Context, role *model.UserAppRole) error
	Delete(ctx context.Context, userID, appID uint) error
	GetUserRolesMap(ctx context.Context, userID uint) (map[string]string, error)
}

type userAppRoleRepository struct {
	db *gorm.DB
}

func NewUserAppRoleRepository(db *gorm.DB) UserAppRoleRepository {
	return &userAppRoleRepository{db: db}
}

func (r *userAppRoleRepository) FindByUserAndApp(ctx context.Context, userID, appID uint) (*model.UserAppRole, error) {
	var role model.UserAppRole
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND app_id = ?", userID, appID).
		First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *userAppRoleRepository) FindByUser(ctx context.Context, userID uint) ([]model.UserAppRole, error) {
	var roles []model.UserAppRole
	if err := r.db.WithContext(ctx).
		Preload("App").
		Where("user_id = ?", userID).
		Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *userAppRoleRepository) FindByApp(ctx context.Context, appID uint, page, pageSize int, search string) ([]model.UserAppRole, int64, error) {
	var roles []model.UserAppRole
	var totalCount int64

	query := r.db.WithContext(ctx).Model(&model.UserAppRole{}).
		Joins("JOIN users ON users.id = user_app_roles.user_id").
		Where("user_app_roles.app_id = ?", appID).
		Where("users.deleted_at IS NULL").
		Where("users.role != ?", "superadmin") // superadmins have global access; never list them per-app

	if search != "" {
		searchPattern := "%" + search + "%"
		query = query.Where("users.email ILIKE ? OR users.name ILIKE ?", searchPattern, searchPattern)
	}

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Preload("User").
		Joins("JOIN users ON users.id = user_app_roles.user_id").
		Where("user_app_roles.app_id = ?", appID).
		Where("users.deleted_at IS NULL").
		Where("users.role != ?", "superadmin").
		Offset(offset).
		Limit(pageSize).
		Order("user_app_roles.id DESC").
		Find(&roles).Error; err != nil {
		return nil, 0, err
	}

	return roles, totalCount, nil
}

func (r *userAppRoleRepository) FindAllByUser(ctx context.Context, userID uint) ([]model.UserAppRole, error) {
	var roles []model.UserAppRole
	if err := r.db.WithContext(ctx).
		Preload("App").
		Where("user_id = ?", userID).
		Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *userAppRoleRepository) Create(ctx context.Context, role *model.UserAppRole) error {
	return r.db.WithContext(ctx).Create(role).Error
}

func (r *userAppRoleRepository) Update(ctx context.Context, role *model.UserAppRole) error {
	return r.db.WithContext(ctx).Save(role).Error
}

func (r *userAppRoleRepository) Delete(ctx context.Context, userID, appID uint) error {
	return r.db.WithContext(ctx).
		Where("user_id = ? AND app_id = ?", userID, appID).
		Delete(&model.UserAppRole{}).Error
}

func (r *userAppRoleRepository) GetUserRolesMap(ctx context.Context, userID uint) (map[string]string, error) {
	var roles []model.UserAppRole
	if err := r.db.WithContext(ctx).
		Preload("App").
		Where("user_id = ?", userID).
		Find(&roles).Error; err != nil {
		return nil, err
	}

	rolesMap := make(map[string]string)
	for _, role := range roles {
		if role.App != nil {
			rolesMap[role.App.ClientID] = string(role.Role)
		}
	}
	return rolesMap, nil
}
