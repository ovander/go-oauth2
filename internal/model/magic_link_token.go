package model

import "time"

// MagicLinkToken represents a single-use passwordless authentication token.
// The plaintext token is never persisted — only its SHA-256 hex digest is stored.
// This ensures that even a full database dump cannot be replayed.
type MagicLinkToken struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	TokenHash string     `gorm:"column:token_hash;uniqueIndex;not null" json:"-"`
	UserID    uint       `gorm:"column:user_id;not null;index" json:"user_id"`
	AppID     uint       `gorm:"column:app_id;not null;index" json:"app_id"`
	Email     string     `gorm:"column:email;not null;index" json:"email"`
	Used      bool       `gorm:"column:used;default:false;index" json:"used"`
	ExpiresAt time.Time  `gorm:"column:expires_at;not null;index" json:"expires_at"`
	UsedAt    *time.Time `gorm:"column:used_at" json:"used_at,omitempty"`
	CreatedAt time.Time  `gorm:"column:inserted_at" json:"created_at"`
}

func (MagicLinkToken) TableName() string {
	return "magic_link_tokens"
}

// IsExpired reports whether the token's TTL has elapsed.
func (t *MagicLinkToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}
