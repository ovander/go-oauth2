package model

import (
	"time"
)

// AlertSeverity represents the severity of an alert
type AlertSeverity string

const (
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertAction represents an action to take when an alert triggers
type AlertAction string

const (
	AlertActionEmail   AlertAction = "email"
	AlertActionWebhook AlertAction = "webhook"
	AlertActionSlack   AlertAction = "slack"
)

// AlertCondition defines when an alert should trigger
type AlertCondition struct {
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
	GroupBy       string `json:"group_by,omitempty"` // ip_address, user_id, app_id
}

// AlertRule defines a rule for triggering alerts
type AlertRule struct {
	ID          uint                   `gorm:"primaryKey" json:"id"`
	Name        string                 `gorm:"type:varchar(100);not null" json:"name"`
	Description string                 `gorm:"type:text" json:"description"`
	EventType   string                 `gorm:"type:varchar(50);not null;index" json:"event_type"`
	Condition   map[string]interface{} `gorm:"type:jsonb;serializer:json;not null" json:"condition"`
	Severity    AlertSeverity          `gorm:"type:varchar(20);not null" json:"severity"`
	Enabled     bool                   `gorm:"default:true" json:"enabled"`
	Actions     []string               `gorm:"type:jsonb;serializer:json;not null" json:"actions"`
	Recipients  []string               `gorm:"type:jsonb;serializer:json" json:"recipients,omitempty"`
	WebhookURL  string                 `gorm:"type:varchar(500)" json:"webhook_url,omitempty"`
	CreatedBy   *uint                  `gorm:"index" json:"created_by,omitempty"`
	Creator     *User                  `gorm:"foreignKey:CreatedBy" json:"creator,omitempty"`
	CreatedAt   time.Time              `gorm:"column:inserted_at" json:"created_at"`
	UpdatedAt   time.Time              `gorm:"column:updated_at" json:"updated_at"`
}

func (AlertRule) TableName() string {
	return "alert_rules"
}

// TriggeredAlert represents an alert that has been triggered
type TriggeredAlert struct {
	ID              uint                   `gorm:"primaryKey" json:"id"`
	RuleID          uint                   `gorm:"index;not null" json:"rule_id"`
	Rule            *AlertRule             `gorm:"foreignKey:RuleID" json:"rule,omitempty"`
	Severity        AlertSeverity          `gorm:"type:varchar(20);not null" json:"severity"`
	Message         string                 `gorm:"type:text;not null" json:"message"`
	Details         map[string]interface{} `gorm:"type:jsonb;serializer:json" json:"details,omitempty"`
	Acknowledged    bool                   `gorm:"default:false;index" json:"acknowledged"`
	AcknowledgedBy  *uint                  `gorm:"index" json:"acknowledged_by,omitempty"`
	Acknowledger    *User                  `gorm:"foreignKey:AcknowledgedBy" json:"acknowledger,omitempty"`
	AcknowledgedAt  *time.Time             `json:"acknowledged_at,omitempty"`
	AcknowledgeNote string                 `gorm:"type:text" json:"acknowledge_note,omitempty"`
	TriggeredAt     time.Time              `gorm:"column:inserted_at;index" json:"triggered_at"`
}

func (TriggeredAlert) TableName() string {
	return "triggered_alerts"
}
