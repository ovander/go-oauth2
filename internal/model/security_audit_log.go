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
	// SecurityEventRefreshTokenReuse: an already-rotated (single-use) refresh
	// token was presented again — a token-theft signal (OAuth 2.0 Security BCP /
	// RFC 9700 §4.14.2). In enforce mode the user's token family is revoked.
	SecurityEventRefreshTokenReuse SecurityEventType = "refresh_token_reuse"
	// SecurityEventClientAuthFailed: a confidential client failed authentication
	// at the token endpoint (missing or wrong client_secret) — a credential-
	// stuffing / brute-force signal (RFC 6749 §3.2.1).
	SecurityEventClientAuthFailed SecurityEventType = "client_auth_failed"

	// OAuth events
	SecurityEventAuthCodeIssued     SecurityEventType = "auth_code_issued"
	SecurityEventAuthCodeExchanged  SecurityEventType = "auth_code_exchanged"
	SecurityEventAuthCodeFailed     SecurityEventType = "auth_code_failed"
	SecurityEventPKCEValidationFail SecurityEventType = "pkce_validation_failed"
	// SecurityEventScopeDenied: a client requested a scope outside its
	// allowed_scopes policy (A1). Emitted in observe and enforce modes.
	SecurityEventScopeDenied SecurityEventType = "scope_denied"

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

	// Delegation (RFC 8693 / EPIC-16): a token-exchange request was processed
	// (in shadow, audited but not issued; in enforce, an exchanged token issued).
	SecurityEventTokenExchange SecurityEventType = "token_exchange"

	// OAuth client lifecycle (#203 / audit §9): administrative changes to a
	// registered client are promoted from the app-activity trail to alertable
	// security events. A rogue client registration, a redirect-URI flipped to an
	// attacker-controlled host, a grant/scope widening, or a secret rotation is a
	// Tier-0 persistence / token-exfiltration vector the SOC must see — not just
	// the app owner via the admin trail.
	SecurityEventClientCreated       SecurityEventType = "client_created"
	SecurityEventClientUpdated       SecurityEventType = "client_updated"
	SecurityEventClientDeleted       SecurityEventType = "client_deleted"
	SecurityEventClientSecretRotated SecurityEventType = "client_secret_rotated" //nolint:gosec // G101 false positive: event type enum constant, not a credential

	// DPoP (RFC 9449): a sender-constraint proof presented at the token endpoint
	// was present but invalid (bad signature, replay, htm/htu/iat mismatch). In
	// observe mode the request still proceeds; in enforce it is rejected. Either
	// way the failure is recorded so the SOC can see DPoP abuse/misconfiguration.
	SecurityEventDPoPValidationFailed SecurityEventType = "dpop_validation_failed"
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
	case SecurityEventClientDeleted, SecurityEventClientSecretRotated:
		// Destructive / credential-changing client-lifecycle actions warrant SOC
		// attention even on the success path (create/update stay at info).
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
