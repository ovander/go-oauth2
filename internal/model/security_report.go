package model

import (
	"time"
)

// SecurityReport is a generated security report, persisted so that reports
// survive restarts and are retrievable from any server instance (the previous
// implementation kept them in a per-process in-memory map, so a report
// generated on one instance was invisible to the others and lost on restart).
//
// The structured report payload is stored in Data as jsonb; only metadata is
// promoted to columns for listing/expiry.
type SecurityReport struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	ReportID string `gorm:"type:varchar(64);uniqueIndex;not null" json:"report_id"`
	Status   string `gorm:"type:varchar(20);not null" json:"status"`
	Type     string `gorm:"type:varchar(50)" json:"type"`
	Format   string `gorm:"type:varchar(10)" json:"format"`
	// Data holds the marshalled SecurityReportData payload. It lives in the
	// model layer as a generic map to avoid a model→dto import cycle.
	Data        map[string]interface{} `gorm:"type:jsonb;serializer:json" json:"data,omitempty"`
	CreatedAt   time.Time              `gorm:"autoCreateTime" json:"created_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	ExpiresAt   *time.Time             `gorm:"index" json:"expires_at,omitempty"`
}

func (SecurityReport) TableName() string {
	return "security_reports"
}

// IsExpired reports whether the report has passed its expiry time.
func (r *SecurityReport) IsExpired() bool {
	return r.ExpiresAt != nil && time.Now().After(*r.ExpiresAt)
}
