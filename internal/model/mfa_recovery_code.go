package model

import "time"

// MFARecoveryCode is a single one-time backup code for MFA recovery. The
// plaintext code is never persisted — only a keyed HMAC-SHA256 digest (keyed by
// SECRET_KEY_BASE) is stored, so a database dump alone cannot reveal or verify a
// code. Each code is single-use: UsedAt is stamped when it is redeemed.
type MFARecoveryCode struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	UserID    uint       `gorm:"column:user_id;not null;index" json:"user_id"`
	CodeHash  string     `gorm:"column:code_hash;not null;index" json:"-"`
	UsedAt    *time.Time `gorm:"column:used_at" json:"used_at,omitempty"`
	CreatedAt time.Time  `gorm:"column:inserted_at" json:"created_at"`
}

func (MFARecoveryCode) TableName() string {
	return "mfa_recovery_codes"
}
