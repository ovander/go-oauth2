package dto

import "time"

// CreateWebhookRequest registers a delivery target (A3).
type CreateWebhookRequest struct {
	// Name is an operator-facing label.
	Name string `json:"name"`
	// URL must be https and must resolve to a public address.
	URL string `json:"url"`
	// AppID scopes the subscription to one client's events. Omitted = global
	// (every app's events).
	AppID *uint `json:"app_id,omitempty"`
	// EventTypes are catalogue names, or the single entry "*" for everything.
	EventTypes []string `json:"event_types"`
	// Active defaults to true.
	Active *bool `json:"active,omitempty"`
}

// UpdateWebhookRequest changes a target. Omitted fields are unchanged. The
// app scope is deliberately not updatable: re-pointing a subscription at
// another client's events is a new subscription decision, not an edit.
type UpdateWebhookRequest struct {
	Name       *string   `json:"name,omitempty"`
	URL        *string   `json:"url,omitempty"`
	EventTypes *[]string `json:"event_types,omitempty"`
	Active     *bool     `json:"active,omitempty"`
}

// WebhookResponse is a subscription as returned by the admin API. It never
// carries the signing secret.
type WebhookResponse struct {
	ID         uint      `json:"id"`
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	AppID      *uint     `json:"app_id,omitempty"`
	EventTypes []string  `json:"event_types"`
	Active     bool      `json:"active"`
	CreatedBy  *uint     `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// WebhookWithSecretResponse is returned once, at creation and on rotation.
type WebhookWithSecretResponse struct {
	WebhookResponse
	// Secret is the HMAC signing key. It is shown exactly once — Socrate stores
	// it encrypted and cannot show it again.
	Secret string `json:"secret"`
}

type WebhookListResponse struct {
	Webhooks   []WebhookResponse `json:"webhooks"`
	TotalCount int64             `json:"total_count"`
}

// WebhookDeliveryResponse is one outbox row.
type WebhookDeliveryResponse struct {
	ID             uint           `json:"id"`
	SubscriptionID uint           `json:"subscription_id"`
	AuditLogID     *uint          `json:"audit_log_id,omitempty"`
	EventType      string         `json:"event_type"`
	Status         string         `json:"status"`
	Attempts       int            `json:"attempts"`
	NextAttemptAt  time.Time      `json:"next_attempt_at"`
	LastStatusCode int            `json:"last_status_code,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
	DeliveredAt    *time.Time     `json:"delivered_at,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	Payload        map[string]any `json:"payload,omitempty"`
}

type WebhookDeliveryListResponse struct {
	Deliveries []WebhookDeliveryResponse `json:"deliveries"`
	TotalCount int64                     `json:"total_count"`
	Page       int                       `json:"page"`
	PageSize   int                       `json:"page_size"`
}
