package repository

import (
	"context"
	"errors"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// ErrGlobalAdminAppRole is returned when an app role would be written for a
// Socrate admin or superadmin.
var ErrGlobalAdminAppRole = errors.New("socrate admins and superadmins cannot hold an app role")

// globalAdminRoles are the platform roles that never hold an app role: an app
// member cannot be a Socrate admin/superadmin, and the reverse.
var globalAdminRoles = []model.UserRole{model.UserRoleAdmin, model.UserRoleSuperadmin}

// notGlobalAdmin keeps a user_app_roles read clear of Socrate admins and
// superadmins. They have global access and are never app members: the admin
// API refuses to assign one, and FindByApp never lists one. A row that exists
// anyway — written directly, e.g. by a data migration from a server that did
// not enforce the rule, or left over when a member was made a Socrate admin —
// is ignored everywhere. It cannot then put a platform account within reach of
// that app's admins (who may act on their app's members, e.g. force a password
// reset), nor add an app role to its tokens.
const notGlobalAdmin = "NOT EXISTS (SELECT 1 FROM users ga WHERE ga.id = user_app_roles.user_id AND ga.role IN ('admin', 'superadmin'))"

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
		Where(notGlobalAdmin).
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
		Where(notGlobalAdmin).
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
		Where("users.role NOT IN ?", globalAdminRoles) // Socrate admins have global access; never list them per-app

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
		Where("users.role NOT IN ?", globalAdminRoles).
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
		Where(notGlobalAdmin).
		Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *userAppRoleRepository) Create(ctx context.Context, role *model.UserAppRole) error {
	if err := r.refuseGlobalAdmin(ctx, role.UserID); err != nil {
		return err
	}
	return r.db.WithContext(ctx).Create(role).Error
}

func (r *userAppRoleRepository) Update(ctx context.Context, role *model.UserAppRole) error {
	if err := r.refuseGlobalAdmin(ctx, role.UserID); err != nil {
		return err
	}
	return r.db.WithContext(ctx).Save(role).Error
}

// refuseGlobalAdmin fails closed: an app role is never written for a Socrate
// admin or superadmin.
// Delete is not guarded, so a stray row can always be removed.
func (r *userAppRoleRepository) refuseGlobalAdmin(ctx context.Context, userID uint) error {
	var n int64
	if err := r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ? AND role IN ?", userID, globalAdminRoles).
		Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return ErrGlobalAdminAppRole
	}
	return nil
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
		Where(notGlobalAdmin).
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
