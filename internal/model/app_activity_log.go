package model

import (
	"time"
)

type EventType string

const (
	EventTypeTokenIssued          EventType = "token_issued"
	EventTypeTokenRefreshed       EventType = "token_refreshed"
	EventTypeTokenRevoked         EventType = "token_revoked"
	EventTypeAuthorizationGranted EventType = "authorization_granted"
	EventTypeLoginSuccess         EventType = "login_success"
	EventTypeLoginFailed          EventType = "login_failed"
	EventTypeLogout               EventType = "logout"
	EventTypePasswordReset        EventType = "password_reset"
	EventTypeSecretRotated        EventType = "secret_rotated"
	EventTypeUserAdded            EventType = "user_added"
	EventTypeUserRemoved          EventType = "user_removed"
	EventTypeRoleChanged          EventType = "role_changed"
	EventTypeAccountLocked        EventType = "account_locked"
	EventTypeAccountUnlocked      EventType = "account_unlocked"
	EventTypeSuspiciousActivity   EventType = "suspicious_activity"
)

type EventCategory string

const (
	EventCategoryOAuth          EventCategory = "oauth"
	EventCategoryAuthentication EventCategory = "authentication"
	EventCategoryAdmin          EventCategory = "admin"
	EventCategorySecurity       EventCategory = "security"
)

type AppActivityLog struct {
	ID            uint                   `gorm:"primaryKey" json:"id"`
	AppID         uint                   `gorm:"column:app_id;not null;index" json:"app_id"`
	UserID        *uint                  `gorm:"column:user_id;index" json:"user_id,omitempty"`
	EventType     EventType              `gorm:"column:event_type;type:varchar(50);index" json:"event_type"`
	EventCategory EventCategory          `gorm:"column:event_category;type:varchar(50);index" json:"event_category"`
	Metadata      map[string]interface{} `gorm:"type:jsonb;serializer:json;default:'{}'" json:"metadata"`
	IPAddress     *string                `gorm:"column:ip_address" json:"ip_address,omitempty"`
	UserAgent     *string                `gorm:"column:user_agent" json:"user_agent,omitempty"`
	Success       bool                   `gorm:"default:true" json:"success"`
	App           *App                   `gorm:"foreignKey:AppID;constraint:OnDelete:CASCADE" json:"app,omitempty"`
	User          *User                  `gorm:"foreignKey:UserID;constraint:OnDelete:SET NULL" json:"user,omitempty"`
	CreatedAt     time.Time              `gorm:"column:inserted_at;index" json:"created_at"`
}

func (AppActivityLog) TableName() string {
	return "app_activity_logs"
}
