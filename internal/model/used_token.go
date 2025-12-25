package model

import (
	"time"
)

// UsedToken tracks tokens that have been used (for single-use enforcement)
type UsedToken struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	TokenJTI  string    `gorm:"column:token_jti;uniqueIndex;not null" json:"token_jti"`
	TokenType string    `gorm:"column:token_type;not null;index" json:"token_type"`
	UserID    uint      `gorm:"column:user_id;not null;index" json:"user_id"`
	UsedAt    time.Time `gorm:"column:used_at;not null" json:"used_at"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null;index" json:"expires_at"`
	CreatedAt time.Time `gorm:"column:inserted_at" json:"created_at"`
}

func (UsedToken) TableName() string {
	return "used_tokens"
}
