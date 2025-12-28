package model

import (
	"time"
)

// BlockedIP represents a blocked IP address
type BlockedIP struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	IPAddress string     `gorm:"type:varchar(45);uniqueIndex;not null" json:"ip_address"`
	Reason    string     `gorm:"type:text" json:"reason,omitempty"`
	BlockedBy *uint      `gorm:"index" json:"blocked_by,omitempty"`
	Blocker   *User      `gorm:"foreignKey:BlockedBy" json:"blocker,omitempty"`
	BlockedAt time.Time  `gorm:"column:inserted_at" json:"blocked_at"`
	ExpiresAt *time.Time `gorm:"index" json:"expires_at,omitempty"`
	Permanent bool       `gorm:"default:false" json:"permanent"`
}

func (BlockedIP) TableName() string {
	return "blocked_ips"
}

// IsExpired returns true if the block has expired
func (b *BlockedIP) IsExpired() bool {
	if b.Permanent {
		return false
	}
	if b.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*b.ExpiresAt)
}

// IsActive returns true if the block is currently active
func (b *BlockedIP) IsActive() bool {
	return !b.IsExpired()
}
