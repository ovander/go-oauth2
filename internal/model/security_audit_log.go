package model

import (
	"time"
)

// SecurityEventType represents different security-related events
type SecurityEventType string

const (
	// Authentication events
	SecurityEventLoginSuccess      SecurityEventType = "login_success"
	SecurityEventLoginFailed       SecurityEventType = "login_failed"
	SecurityEventLogout            SecurityEventType = "logout"
	SecurityEventAccountLocked     SecurityEventType = "account_locked"
	SecurityEventAccountUnlocked   SecurityEventType = "account_unlocked"
	SecurityEventPasswordChanged   SecurityEventType = "password_changed"
	SecurityEventPasswordResetReq  SecurityEventType = "password_reset_requested"
	SecurityEventPasswordResetUsed SecurityEventType = "password_reset_used"
	SecurityEventEmailVerified     SecurityEventType = "email_verified"
	SecurityEventEmailChangeReq    SecurityEventType = "email_change_requested"
	SecurityEventEmailChanged      SecurityEventType = "email_changed"
	SecurityEventUserRegistered    SecurityEventType = "user_registered"
	SecurityEventUserInvited       SecurityEventType = "user_invited"
	SecurityEventInviteAccepted    SecurityEventType = "invite_accepted"
	SecurityEventEmailSendFailed   SecurityEventType = "email_send_failed"

	// Token events
	SecurityEventTokenIssued      SecurityEventType = "token_issued"
	SecurityEventTokenRefreshed   SecurityEventType = "token_refreshed"
	SecurityEventTokenRevoked     SecurityEventType = "token_revoked"
	SecurityEventTokenRevokedAll  SecurityEventType = "all_tokens_revoked" //nolint:gosec // G101 false positive: event type enum constant, not a credential
	SecurityEventInvalidTokenUsed SecurityEventType = "invalid_token_used"
	SecurityEventExpiredTokenUsed SecurityEventType = "expired_token_used"
	SecurityEventRevokedTokenUsed SecurityEventType = "revoked_token_used"

	// OAuth events
	SecurityEventAuthCodeIssued     SecurityEventType = "auth_code_issued"
	SecurityEventAuthCodeExchanged  SecurityEventType = "auth_code_exchanged"
	SecurityEventAuthCodeFailed     SecurityEventType = "auth_code_failed"
	SecurityEventPKCEValidationFail SecurityEventType = "pkce_validation_failed"

	// Suspicious activity
	SecurityEventSuspiciousActivity SecurityEventType = "suspicious_activity"
	SecurityEventRateLimitExceeded  SecurityEventType = "rate_limit_exceeded"
	SecurityEventBruteForceDetected SecurityEventType = "brute_force_detected"

	// Integrity (RFC-007): a stored audit row failed HMAC verification.
	SecurityEventAuditIntegrityViolation SecurityEventType = "audit_integrity_violation"

	// MFA (RFC-011): an admin subject to the MFA policy logged in (observe) or
	// was denied (enforce) without having MFA enrolled.
	SecurityEventMFAPolicyViolation SecurityEventType = "mfa_policy_violation"
	// MFA (RFC-011): a one-time recovery code was redeemed to satisfy login
	// step-up (in place of a TOTP code).
	SecurityEventMFARecoveryUsed SecurityEventType = "mfa_recovery_code_used"
)

// SecuritySeverity indicates the severity level of the event
type SecuritySeverity string

const (
	SecuritySeverityInfo     SecuritySeverity = "info"
	SecuritySeverityWarning  SecuritySeverity = "warning"
	SecuritySeverityError    SecuritySeverity = "error"
	SecuritySeverityCritical SecuritySeverity = "critical"
)

// SecurityAuditLog represents a security audit log entry
type SecurityAuditLog struct {
	ID        uint              `gorm:"primaryKey" json:"id"`
	UserID    *uint             `gorm:"index" json:"user_id,omitempty"`
	AppID     *uint             `gorm:"index" json:"app_id,omitempty"`
	EventType SecurityEventType `gorm:"type:varchar(50);index;not null" json:"event_type"`
	Severity  SecuritySeverity  `gorm:"type:varchar(20);index;not null" json:"severity"`
	IPAddress string            `gorm:"type:varchar(45)" json:"ip_address"` // IPv6 max length
	UserAgent string            `gorm:"type:varchar(500)" json:"user_agent"`
	// CorrelationID links this audit row to the request that produced it for
	// end-to-end tracing (RFC-007/RFC-008). Empty when produced outside a
	// request context.
	CorrelationID string                 `gorm:"type:varchar(64);index" json:"correlation_id,omitempty"`
	Details       map[string]interface{} `gorm:"type:jsonb;serializer:json" json:"details"`
	// RowHash is a keyed HMAC over the row's immutable content, making the row
	// tamper-evident (RFC-007). Empty when integrity stamping is disabled (no
	// configured secret).
	RowHash string `gorm:"column:row_hash;type:varchar(64);index" json:"row_hash,omitempty"`
	// PrevHash links this row to the previous chained row's RowHash, forming a
	// hash chain so that deletion or reordering of rows is detectable (RFC-007),
	// not just in-place mutation. Empty for the genesis row and for rows written
	// before chaining was enabled.
	PrevHash  string    `gorm:"column:prev_hash;type:varchar(64)" json:"prev_hash,omitempty"`
	Success   bool      `gorm:"index" json:"success"`
	User      *User     `gorm:"foreignKey:UserID" json:"user,omitempty"`
	App       *App      `gorm:"foreignKey:AppID" json:"app,omitempty"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

func (SecurityAuditLog) TableName() string {
	return "security_audit_logs"
}

// GetSeverityForEvent returns the appropriate severity for an event type
func GetSeverityForEvent(eventType SecurityEventType, success bool) SecuritySeverity {
	switch eventType {
	case SecurityEventLoginFailed, SecurityEventInvalidTokenUsed, SecurityEventExpiredTokenUsed:
		return SecuritySeverityWarning
	case SecurityEventAccountLocked, SecurityEventRateLimitExceeded:
		return SecuritySeverityError
	case SecurityEventBruteForceDetected, SecurityEventSuspiciousActivity, SecurityEventRevokedTokenUsed,
		SecurityEventAuditIntegrityViolation:
		return SecuritySeverityCritical
	default:
		if !success {
			return SecuritySeverityWarning
		}
		return SecuritySeverityInfo
	}
}
