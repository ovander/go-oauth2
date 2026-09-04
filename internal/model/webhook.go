package model

import (
	"sort"
	"strings"
	"time"
)

// WebhookEventType is the name of an event as it appears on the wire, in a
// subscription's filter and in the delivery log. Names are deliberately not the
// internal SecurityEventType values: the audit vocabulary is an implementation
// detail that changes as the server grows, while a webhook event name is a
// public contract with someone else's code.
type WebhookEventType string

// Event catalogue v1 (A3). Every entry maps from exactly one SecurityEventType,
// so a delivery can never exist without the audit row that produced it.
const (
	WebhookUserCreated  WebhookEventType = "user.created"
	WebhookUserVerified WebhookEventType = "user.verified"
	WebhookUserInvited  WebhookEventType = "user.invited"
	WebhookUserLocked   WebhookEventType = "user.locked"
	WebhookUserUnlocked WebhookEventType = "user.unlocked"

	WebhookLoginSucceeded WebhookEventType = "login.succeeded"
	WebhookLoginFailed    WebhookEventType = "login.failed"
	WebhookLoginMFADenied WebhookEventType = "login.mfa_policy_violation"

	WebhookClientCreated       WebhookEventType = "client.created"
	WebhookClientUpdated       WebhookEventType = "client.updated"
	WebhookClientDeleted       WebhookEventType = "client.deleted"
	WebhookClientSecretRotated WebhookEventType = "client.secret_rotated" //nolint:gosec // G101 false positive: event name, not a credential

	WebhookTokenRevokedAll WebhookEventType = "token.revoked_all" //nolint:gosec // G101 false positive: event name, not a credential
	WebhookTokenExchanged  WebhookEventType = "token.exchanged"

	WebhookSecurityBruteForce         WebhookEventType = "security.brute_force_detected"
	WebhookSecurityRateLimitExceeded  WebhookEventType = "security.rate_limit_exceeded"
	WebhookSecuritySuspicious         WebhookEventType = "security.suspicious_activity"
	WebhookSecurityRefreshReuse       WebhookEventType = "security.refresh_token_reuse" //nolint:gosec // G101 false positive: event name, not a credential
	WebhookSecurityScopeDenied        WebhookEventType = "security.scope_denied"
	WebhookSecurityIntegrityViolation WebhookEventType = "security.audit_integrity_violation"
	WebhookSecurityDPoPFailed         WebhookEventType = "security.dpop_validation_failed"
)

// webhookEventForAudit maps an internal audit event to its public webhook
// event. An audit event absent from this map produces no webhook — the
// catalogue is an allow-list, so a new internal event type never starts leaking
// to subscribers by default.
var webhookEventForAudit = map[SecurityEventType]WebhookEventType{
	SecurityEventUserRegistered:  WebhookUserCreated,
	SecurityEventEmailVerified:   WebhookUserVerified,
	SecurityEventUserInvited:     WebhookUserInvited,
	SecurityEventAccountLocked:   WebhookUserLocked,
	SecurityEventAccountUnlocked: WebhookUserUnlocked,

	SecurityEventLoginSuccess:       WebhookLoginSucceeded,
	SecurityEventLoginFailed:        WebhookLoginFailed,
	SecurityEventMFAPolicyViolation: WebhookLoginMFADenied,

	SecurityEventClientCreated:       WebhookClientCreated,
	SecurityEventClientUpdated:       WebhookClientUpdated,
	SecurityEventClientDeleted:       WebhookClientDeleted,
	SecurityEventClientSecretRotated: WebhookClientSecretRotated,

	SecurityEventTokenRevokedAll: WebhookTokenRevokedAll,
	SecurityEventTokenExchange:   WebhookTokenExchanged,

	SecurityEventBruteForceDetected:      WebhookSecurityBruteForce,
	SecurityEventRateLimitExceeded:       WebhookSecurityRateLimitExceeded,
	SecurityEventSuspiciousActivity:      WebhookSecuritySuspicious,
	SecurityEventRefreshTokenReuse:       WebhookSecurityRefreshReuse,
	SecurityEventScopeDenied:             WebhookSecurityScopeDenied,
	SecurityEventAuditIntegrityViolation: WebhookSecurityIntegrityViolation,
	SecurityEventDPoPValidationFailed:    WebhookSecurityDPoPFailed,
}

// WebhookEventForAudit returns the public webhook event for an audit event, and
// false when the audit event is not part of the catalogue.
func WebhookEventForAudit(t SecurityEventType) (WebhookEventType, bool) {
	e, ok := webhookEventForAudit[t]
	return e, ok
}

// WebhookEventCatalogue returns every subscribable event name, sorted. It backs
// the admin API's catalogue endpoint so a console can render the picker without
// hard-coding the list.
func WebhookEventCatalogue() []string {
	names := make([]string, 0, len(webhookEventForAudit))
	for _, e := range webhookEventForAudit {
		names = append(names, string(e))
	}
	sort.Strings(names)
	return names
}

// IsKnownWebhookEvent reports whether name is in the catalogue.
func IsKnownWebhookEvent(name string) bool {
	for _, e := range webhookEventForAudit {
		if string(e) == name {
			return true
		}
	}
	return false
}

// WebhookEventWildcard subscribes to every event in the catalogue, including
// ones added by a later release.
const WebhookEventWildcard = "*"

// WebhookSubscription is an operator-registered delivery target.
type WebhookSubscription struct {
	ID uint `gorm:"primaryKey" json:"id"`
	// AppID scopes the subscription to one client's events. Nil means a global
	// subscription that receives events for every app (global admin only).
	AppID *uint `gorm:"column:app_id;index" json:"app_id,omitempty"`
	// Name is an operator-facing label.
	Name string `gorm:"not null" json:"name"`
	// URL is the https target, vetted by internal/shared/ssrf at write time and
	// re-vetted at connect time.
	URL string `gorm:"column:url;not null" json:"url"`
	// SecretEnc is the signing secret, encrypted at rest with the same AES-GCM
	// helper as TOTP secrets (auth.EncryptSecret). Never serialized — the
	// plaintext is shown once, at creation or rotation.
	SecretEnc string `gorm:"column:secret_enc;not null" json:"-"`
	// EventTypes is the subscription filter: catalogue names, or the single
	// entry "*" for everything.
	EventTypes StringArray `gorm:"type:text[];column:event_types" json:"event_types"`
	// Active gates delivery without losing the registration.
	Active bool `gorm:"default:true" json:"active"`
	// CreatedBy records the admin who registered the target.
	CreatedBy *uint     `gorm:"column:created_by" json:"created_by,omitempty"`
	CreatedAt time.Time `gorm:"column:inserted_at" json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (WebhookSubscription) TableName() string {
	return "webhook_subscriptions"
}

// Matches reports whether this subscription wants an event of this type, for
// this app. A subscription scoped to an app never sees another app's events,
// and an inactive subscription matches nothing.
func (s *WebhookSubscription) Matches(event WebhookEventType, appID *uint) bool {
	if !s.Active {
		return false
	}
	if s.AppID != nil {
		if appID == nil || *appID != *s.AppID {
			return false
		}
	}
	for _, e := range s.EventTypes {
		if e == WebhookEventWildcard || e == string(event) {
			return true
		}
	}
	return false
}

// Webhook delivery lifecycle.
const (
	// WebhookDeliveryPending is queued (or waiting for its next attempt).
	WebhookDeliveryPending = "pending"
	// WebhookDeliveryDelivered got a 2xx from the target.
	WebhookDeliveryDelivered = "delivered"
	// WebhookDeliveryDead exhausted its attempts. Terminal — a dead delivery is
	// kept for the operator to inspect and replay, never silently dropped.
	WebhookDeliveryDead = "dead"
)

// WebhookDelivery is one outbox row: a single event owed to a single
// subscription. It is written in the same transaction as the security audit row
// that produced it, so a delivery can never exist without its audit entry — and
// an audit write that fails takes its deliveries down with it.
type WebhookDelivery struct {
	ID             uint             `gorm:"primaryKey" json:"id"`
	SubscriptionID uint             `gorm:"column:subscription_id;index;not null" json:"subscription_id"`
	AuditLogID     *uint            `gorm:"column:audit_log_id;index" json:"audit_log_id,omitempty"`
	EventType      WebhookEventType `gorm:"column:event_type;type:varchar(64);index;not null" json:"event_type"`
	// Payload is the exact JSON body that will be signed and sent. It is frozen
	// at enqueue time so a retry cannot deliver a different body than the first
	// attempt, and so the signature stays reproducible.
	Payload  JSONMap `gorm:"type:jsonb;column:payload" json:"payload"`
	Status   string  `gorm:"type:varchar(16);index;not null;default:pending" json:"status"`
	Attempts int     `gorm:"not null;default:0" json:"attempts"`
	// NextAttemptAt is when the dispatcher may next claim this row.
	NextAttemptAt  time.Time  `gorm:"column:next_attempt_at;index;not null" json:"next_attempt_at"`
	LastStatusCode int        `gorm:"column:last_status_code" json:"last_status_code,omitempty"`
	LastError      string     `gorm:"column:last_error;type:varchar(500)" json:"last_error,omitempty"`
	DeliveredAt    *time.Time `gorm:"column:delivered_at" json:"delivered_at,omitempty"`
	CreatedAt      time.Time  `gorm:"column:inserted_at" json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (WebhookDelivery) TableName() string {
	return "webhook_deliveries"
}

// NormalizeEventFilter trims, de-duplicates and sorts a subscription filter.
// A filter containing the wildcard collapses to just the wildcard, so
// ["*", "user.created"] cannot later be misread as a narrower subscription.
func NormalizeEventFilter(events []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(events))
	for _, e := range events {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		if e == WebhookEventWildcard {
			return []string{WebhookEventWildcard}
		}
		seen[e] = true
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}
