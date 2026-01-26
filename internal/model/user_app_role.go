package model

import (
	"time"
)

type AppRole string

const (
	AppRoleAdmin   AppRole = "admin"
	AppRoleManager AppRole = "manager"
	AppRoleEditor  AppRole = "editor"
	AppRoleViewer  AppRole = "viewer"
	AppRoleUser    AppRole = "user"
)

// ValidAppRoles contains all valid app roles
var ValidAppRoles = []AppRole{
	AppRoleAdmin,
	AppRoleManager,
	AppRoleEditor,
	AppRoleViewer,
	AppRoleUser,
}

// IsValidAppRole checks if the given role is valid
func IsValidAppRole(role string) bool {
	for _, r := range ValidAppRoles {
		if string(r) == role {
			return true
		}
	}
	return false
}

type UserAppRole struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	UserID     uint      `gorm:"not null;uniqueIndex:idx_user_app_roles_user_app" json:"user_id"`
	AppID      uint      `gorm:"not null;uniqueIndex:idx_user_app_roles_user_app" json:"app_id"`
	Role       AppRole   `gorm:"type:varchar(20);default:user" json:"role"`
	InviteSent bool      `gorm:"column:invite_sent;default:false" json:"invite_sent"`
	User       *User     `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`
	App        *App      `gorm:"foreignKey:AppID;constraint:OnDelete:CASCADE" json:"app,omitempty"`
	CreatedAt  time.Time `gorm:"column:inserted_at" json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (UserAppRole) TableName() string {
	return "user_app_roles"
}
