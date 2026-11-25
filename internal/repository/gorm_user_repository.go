package repository

import (
	"context"
	"errors"
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
	// statements own (userGuardedColumns): the token version, the lockout
	// state and the password. Saving a user loaded before a concurrent session
	// revocation, failed sign-in or password change therefore cannot undo it.
	// Those columns change only through IncrementTokenVersion, SetPassword,
	// IncrementFailedLoginAttempts, ResetFailedLoginAttempts, LockAccount and
	// UpdateProfile.
	// It only updates an existing, non-deleted user: a user deleted since it
	// was read stays deleted, and Update returns gorm.ErrRecordNotFound.
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
	// RecordLogin records a successful sign-in at time at: it writes
	// last_login (and last_login_attempt too when attempt is set) and
	// updated_at, and no other column. A sign-in loads the user before it
	// checks the password and the second factor; a full-row Update of that
	// copy would write back whatever changed meanwhile (an MFA enrolment or
	// reset, a role, an email). It returns gorm.ErrRecordNotFound when no such
	// non-deleted user exists.
	RecordLogin(ctx context.Context, userID uint, at time.Time, attempt bool) error
}

// PasswordChange is a new password hash and what is recorded with it.
type PasswordChange struct {
	HashedPassword string
	// ClearMustChangePassword clears must_change_password: the user chose
	// this password.
	ClearMustChangePassword bool
	// ChangedAt, when set, is stored as password_changed_at.
	ChangedAt *time.Time
	// ConfirmedAt, when set, also marks the user verified and stores it as
	// confirmed_at (an invited account choosing its first password).
	ConfirmedAt *time.Time
	// OnlyIfUnchangedSince, when set, applies the change only if
	// password_changed_at still holds the value it carries (nil: never
	// changed): a password-reset link checked against the last change cannot
	// overwrite a change that lands between that check and this write (#366).
	// Otherwise SetPassword returns ErrPasswordChangedMeanwhile and writes
	// nothing.
	OnlyIfUnchangedSince *PasswordState
}

// PasswordState is the password_changed_at a guarded change expects.
type PasswordState struct {
	ChangedAt *time.Time
}

// ErrPasswordChangedMeanwhile is returned by a guarded SetPassword when the
// password changed after the caller read it.
var ErrPasswordChangedMeanwhile = errors.New("the password changed meanwhile")

// userGuardedColumns are the users columns that Update never writes: each is
// changed only by a targeted statement (an increment, a reset, a lock, a
// password change), so a full-row save of a user loaded earlier would move it
// back. The password columns are among them: a save racing a password change
// would otherwise restore the old password. So is invite_app_id, set at
// creation or by ClaimInviteApp: a save racing a claim would otherwise clear
// it and let another app's invite activate the account. mfa_last_step is
// guarded the same way by its read-only GORM tag (model.User.MFALastStep).
var userGuardedColumns = []string{
	"token_version", "failed_login_attempts", "locked_until",
	"hashed_password", "password_changed_at", "must_change_password",
	"invite_app_id",
}

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

// userUpdateOmitted are the columns Update leaves alone: the guarded ones, the
// identity and creation time, and the deletion state.
var userUpdateOmitted = append([]string{"id", "created_at", "deleted_at"}, userGuardedColumns...)

func (r *userRepository) Update(ctx context.Context, user *model.User) error {
	// An UPDATE of every other column (Select("*") writes zero values too),
	// not Save: when Save's UPDATE matches no row, GORM retries it as an
	// INSERT ... ON CONFLICT that clears deleted_at, bringing back a user
	// deleted since it was read. The soft-delete scope keeps this UPDATE off
	// deleted rows.
	res := r.db.WithContext(ctx).Model(user).Select("*").Omit(userUpdateOmitted...).Updates(user)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
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
	if change.ConfirmedAt != nil {
		columns["is_verified"] = true
		columns["confirmed_at"] = *change.ConfirmedAt
	}
	// One UPDATE statement (updated_at is set with it): the new hash and the
	// revocation cannot be saved apart.
	q := r.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID)
	if g := change.OnlyIfUnchangedSince; g != nil {
		if g.ChangedAt == nil {
			q = q.Where("password_changed_at IS NULL")
		} else {
			q = q.Where("password_changed_at = ?", *g.ChangedAt)
		}
	}
	res := q.Updates(columns)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		if change.OnlyIfUnchangedSince != nil {
			return ErrPasswordChangedMeanwhile
		}
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

func (r *userRepository) RecordLogin(ctx context.Context, userID uint, at time.Time, attempt bool) error {
	columns := map[string]interface{}{
		"last_login": at,
		"updated_at": at,
	}
	if attempt {
		columns["last_login_attempt"] = at
	}
	// Model(&model.User{}) keeps the soft-delete scope: a user deleted since
	// it was read stays deleted.
	res := r.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).Updates(columns)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
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
