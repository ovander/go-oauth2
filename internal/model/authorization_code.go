package model

import (
	"time"
)

// AuthorizationCode represents a stored OAuth2 authorization code
type AuthorizationCode struct {
	ID                  uint              `gorm:"primaryKey" json:"id"`
	Code                string            `gorm:"column:code;uniqueIndex;not null" json:"-"`
	UserID              uint              `gorm:"column:user_id;not null;index" json:"user_id"`
	AppID               uint              `gorm:"column:app_id;not null;index" json:"app_id"`
	ClientID            string            `gorm:"column:client_id;not null" json:"client_id"`
	RedirectURI         string            `gorm:"column:redirect_uri;not null" json:"redirect_uri"`
	Scope               string            `gorm:"column:scope" json:"scope"`
	Nonce               string            `gorm:"column:nonce" json:"nonce"`
	CodeChallenge       string            `gorm:"column:code_challenge" json:"code_challenge"`
	CodeChallengeMethod string            `gorm:"column:code_challenge_method" json:"code_challenge_method"`
	Role                string            `gorm:"column:role" json:"role"`
	AppRoles            map[string]string `gorm:"type:jsonb;serializer:json;default:'{}'" json:"app_roles"`
	Used                bool              `gorm:"column:used;default:false;index" json:"used"`
	ExpiresAt           time.Time         `gorm:"column:expires_at;not null;index" json:"expires_at"`
	CreatedAt           time.Time         `gorm:"column:inserted_at" json:"created_at"`
}

func (AuthorizationCode) TableName() string {
	return "authorization_codes"
}

// IsExpired checks if the authorization code has expired
func (c *AuthorizationCode) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}
