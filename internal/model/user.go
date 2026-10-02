package model

import (
	"time"

	"gorm.io/gorm"
)

type UserRole string

const (
	UserRoleUser       UserRole = "user"
	UserRoleAdmin      UserRole = "admin"
	UserRoleSuperadmin UserRole = "superadmin"
)

type User struct {
	ID                  uint           `gorm:"primaryKey" json:"id"`
	Name                string         `gorm:"not null" json:"name"`
	Email               string         `gorm:"uniqueIndex:idx_users_email_active,where:deleted_at IS NULL;not null" json:"email"`
	HashedPassword      string         `gorm:"column:hashed_password" json:"-"`
	IsVerified          bool           `gorm:"default:false" json:"is_verified"`
	Role                UserRole       `gorm:"type:varchar(20);default:user" json:"role"`
	MustChangePassword  bool           `gorm:"column:must_change_password;default:false" json:"must_change_password"`
	Title               *string        `json:"title,omitempty"`
	Division            *string        `json:"division,omitempty"`
	Company             *string        `json:"company,omitempty"`
	Country             *string        `json:"country,omitempty"`
	Phone               *string        `json:"phone,omitempty"`
	JobTitle            *string        `gorm:"column:job_title" json:"job_title,omitempty"`
	Department          *string        `json:"department,omitempty"`
	Language            *string        `json:"language,omitempty"`
	Timezone            *string        `json:"timezone,omitempty"`
	LastLogin           *time.Time     `gorm:"column:last_login" json:"last_login,omitempty"`
	ConsentVersion      *string        `gorm:"column:consent_version" json:"consent_version,omitempty"`
	ConsentDone         bool           `gorm:"column:consent_done;default:false" json:"consent_done"`
	Source              string         `gorm:"default:manual" json:"source"`
	TokenVersion        int            `gorm:"column:token_version;default:1" json:"-"`
	ConfirmedAt         *time.Time     `gorm:"column:confirmed_at" json:"confirmed_at,omitempty"`
	DeletedAt           gorm.DeletedAt `gorm:"index" json:"-"`
	FailedLoginAttempts int            `gorm:"column:failed_login_attempts;default:0" json:"-"`
	LockedUntil         *time.Time     `gorm:"column:locked_until;index" json:"-"`
	LastLoginAttempt    *time.Time     `gorm:"column:last_login_attempt" json:"-"`
	PasswordChangedAt   *time.Time     `gorm:"column:password_changed_at" json:"-"`
	// MFASecret is the user's TOTP secret, stored encrypted at rest
	// (auth.EncryptSecret). Empty when MFA is not enrolled. Never serialized.
	MFASecret  string `gorm:"column:mfa_secret" json:"-"`
	MFAEnabled bool   `gorm:"column:mfa_enabled;default:false" json:"mfa_enabled"`
	// Attributes is free-form per-user data an operator attaches to the user
	// (tier, cost centre, employee number, …). It is never put in a token by
	// itself: a client must opt in by declaring a claim mapping that names
	// `user.attributes.<key>` (A2). Empty by default.
	Attributes JSONMap `gorm:"type:jsonb;column:attributes" json:"attributes,omitempty"`

	// AvatarURL is an https URL of the user's picture, hosted by an
	// application (Socrate stores only the URL). Returned as the OIDC
	// "picture" claim at userinfo. Nil when not set.
	AvatarURL *string `gorm:"column:avatar_url" json:"avatar_url,omitempty"`

	CreatedAt time.Time `gorm:"column:inserted_at" json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (User) TableName() string {
	return "users"
}

func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

func (u *User) IsGlobalAdmin() bool {
	return u.Role == UserRoleAdmin || u.Role == UserRoleSuperadmin
}
