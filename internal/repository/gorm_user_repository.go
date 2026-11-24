package repository

import (
	"context"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

type UserRepository interface {
	FindAll(ctx context.Context, page, pageSize int) ([]model.User, int64, error)
	FindByID(ctx context.Context, id uint) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	FindByRole(ctx context.Context, role model.UserRole) ([]model.User, error)
	CountByRole(ctx context.Context, role model.UserRole) (int64, error)
	Create(ctx context.Context, user *model.User) error
	// Update saves the user's row, except the columns that targeted
	// statements own (userGuardedColumns): the token version and the
	// lockout state. Saving a user loaded before a concurrent session
	// revocation or failed sign-in therefore cannot undo it. Those columns
	// change only through IncrementTokenVersion, SetPassword,
	// IncrementFailedLoginAttempts, ResetFailedLoginAttempts and LockAccount.
	Update(ctx context.Context, user *model.User) error
	// SetPassword stores a new password hash and increments the token
	// version in the same statement, so the user's existing sessions end
	// with the old password: both are saved or neither is. It returns
	// gorm.ErrRecordNotFound when no such user exists.
	SetPassword(ctx context.Context, userID uint, change PasswordChange) error
	// UpdateProfile writes the user's name, email, password hash,
	// password-change time and update time, and no other column, so it cannot
	// overwrite a concurrent change to the others (token version, lockout).
	// With revokeSessions it also increments the token version in the same
	// transaction, ending the user's existing sessions.
	UpdateProfile(ctx context.Context, user *model.User, revokeSessions bool) error
	Delete(ctx context.Context, id uint) error
	IncrementTokenVersion(ctx context.Context, userID uint) error
	IncrementFailedLoginAttempts(ctx context.Context, userID uint) error
	ResetFailedLoginAttempts(ctx context.Context, userID uint) error
	LockAccount(ctx context.Context, userID uint, until *time.Time) error
	// ClaimInviteApp records appID as the app whose invite activates the
	// pending account userID, only if no app is recorded yet. It reports
	// whether it did (false: another app is already recorded).
	ClaimInviteApp(ctx context.Context, userID, appID uint) (bool, error)
	// AdvanceMFAStep records step as the user's last accepted TOTP time step,
	// only if it is later than the one recorded. It reports whether it did
	// (false: that step or a later one was already used).
	AdvanceMFAStep(ctx context.Context, userID uint, step int64) (bool, error)
}

// PasswordChange is a new password hash and what is recorded with it.
type PasswordChange struct {
	HashedPassword string
	// ClearMustChangePassword clears must_change_password: the user chose
	// this password.
	ClearMustChangePassword bool
	// ChangedAt, when set, is stored as password_changed_at.
	ChangedAt *time.Time
}

// userGuardedColumns are the users columns that Update never writes: each is
// changed only by a targeted statement that reads and writes it in the
// database (an increment, a reset, a lock), so a full-row save of a user
// loaded earlier would move it back. mfa_last_step is guarded the same way by
// its read-only GORM tag (model.User.MFALastStep).
var userGuardedColumns = []string{"token_version", "failed_login_attempts", "locked_until"}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) FindAll(ctx context.Context, page, pageSize int) ([]model.User, int64, error) {
	var users []model.User
	var totalCount int64

	query := r.db.WithContext(ctx).Model(&model.User{})

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("id DESC").Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, totalCount, nil
}

func (r *userRepository) FindByID(ctx context.Context, id uint) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByRole(ctx context.Context, role model.UserRole) ([]model.User, error) {
	var users []model.User
	if err := r.db.WithContext(ctx).Where("role = ?", role).Order("id DESC").Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (r *userRepository) CountByRole(ctx context.Context, role model.UserRole) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.User{}).Where("role = ?", role).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *userRepository) Create(ctx context.Context, user *model.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepository) Update(ctx context.Context, user *model.User) error {
	return r.db.WithContext(ctx).Omit(userGuardedColumns...).Save(user).Error
}

func (r *userRepository) SetPassword(ctx context.Context, userID uint, change PasswordChange) error {
	columns := map[string]interface{}{
		"hashed_password": change.HashedPassword,
		"token_version":   gorm.Expr("token_version + 1"),
	}
	if change.ClearMustChangePassword {
		columns["must_change_password"] = false
	}
	if change.ChangedAt != nil {
		columns["password_changed_at"] = *change.ChangedAt
	}
	// One UPDATE statement (updated_at is set with it): the new hash and the
	// revocation cannot be saved apart.
	res := r.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).Updates(columns)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *userRepository) UpdateProfile(ctx context.Context, user *model.User, revokeSessions bool) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.User{}).Where("id = ?", user.ID).
			Select("name", "email", "hashed_password", "password_changed_at", "updated_at").
			Updates(&model.User{
				Name:              user.Name,
				Email:             user.Email,
				HashedPassword:    user.HashedPassword,
				PasswordChangedAt: user.PasswordChangedAt,
				UpdatedAt:         user.UpdatedAt,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		if !revokeSessions {
			return nil
		}
		return tx.Model(&model.User{}).Where("id = ?", user.ID).
			UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error
	})
}

func (r *userRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&model.User{}, id).Error
}

func (r *userRepository) IncrementTokenVersion(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", userID).
		UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error
}

func (r *userRepository) IncrementFailedLoginAttempts(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", userID).
		UpdateColumn("failed_login_attempts", gorm.Expr("failed_login_attempts + 1")).Error
}

func (r *userRepository) ResetFailedLoginAttempts(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"failed_login_attempts": 0,
			"locked_until":          nil,
		}).Error
}

func (r *userRepository) LockAccount(ctx context.Context, userID uint, until *time.Time) error {
	return r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", userID).
		Update("locked_until", until).Error
}

func (r *userRepository) ClaimInviteApp(ctx context.Context, userID, appID uint) (bool, error) {
	res := r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ? AND invite_app_id IS NULL", userID).
		Update("invite_app_id", appID)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (r *userRepository) AdvanceMFAStep(ctx context.Context, userID uint, step int64) (bool, error) {
	// Raw SQL: the column is read-only for GORM writes (model.User.MFALastStep).
	res := r.db.WithContext(ctx).Exec(
		"UPDATE users SET mfa_last_step = ? WHERE id = ? AND mfa_last_step < ?", step, userID, step)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}
