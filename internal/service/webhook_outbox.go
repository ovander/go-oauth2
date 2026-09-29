package service

import (
	"context"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// WebhookOutbox turns a security audit row into pending delivery rows, written
// in the same transaction as that audit row (A3). It implements
// repository.AuditOutboxWriter.
//
// It runs on the audit write path, which is on the request hot path, so it does
// no I/O of its own beyond the one INSERT: routing is decided against the
// service's in-memory subscription cache.
type WebhookOutbox struct {
	subs interface {
		Subscriptions() []model.WebhookSubscription
	}
	// enabled is the WEBHOOKS_MODE kill switch. When false nothing is enqueued,
	// which is the default.
	enabled bool
}

// NewWebhookOutbox builds the outbox producer. A disabled outbox is still
// installed (so the wiring is uniform) but never writes a row.
func NewWebhookOutbox(svc WebhookService, enabled bool) *WebhookOutbox {
	return &WebhookOutbox{subs: svc, enabled: enabled}
}

// WriteOutbox enqueues one delivery per matching subscription. The payload is
// frozen here: a retry re-sends these exact bytes, so the signature stays
// reproducible and a subscriber never sees an event mutate between attempts.
func (o *WebhookOutbox) WriteOutbox(ctx context.Context, tx *gorm.DB, log *model.SecurityAuditLog) error {
	deliveries := o.DeliveriesFor(log)
	for i := range deliveries {
		if err := tx.Create(&deliveries[i]).Error; err != nil {
			return err
		}
	}
	return nil
}

// DeliveriesFor is the routing decision, separated from the insert so it can be
// exercised without a database. It returns one pending delivery per matching
// subscription, or nothing when webhooks are off, the audit event is outside
// the catalogue, or no subscription wants it.
func (o *WebhookOutbox) DeliveriesFor(log *model.SecurityAuditLog) []model.WebhookDelivery {
	if o == nil || !o.enabled || log == nil {
		return nil
	}

	event, ok := model.WebhookEventForAudit(log.EventType)
	if !ok {
		// Not in the catalogue — an internal-only audit event.
		return nil
	}

	subs := o.subs.Subscriptions()
	if len(subs) == 0 {
		return nil
	}

	now := time.Now()
	payload := webhookPayload(event, log)

	var out []model.WebhookDelivery
	for i := range subs {
		sub := &subs[i]
		if !sub.Matches(event, log.AppID) {
			continue
		}
		delivery := model.WebhookDelivery{
			SubscriptionID: sub.ID,
			EventType:      event,
			Payload:        payload,
			Status:         model.WebhookDeliveryPending,
			NextAttemptAt:  now,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if log.ID != 0 {
			id := log.ID
			delivery.AuditLogID = &id
		}
		out = append(out, delivery)
	}
	return out
}

// webhookPayload builds the JSON body a subscriber receives.
//
// What is deliberately *not* here: the audit row's integrity hashes (internal
// evidence, not a subscriber's business), the user agent, and any token,
// secret or credential — none of which appear in an audit row's details in the
// first place, but the omission is explicit so it stays that way. The IP is
// included because the security events in the catalogue (brute force, rate
// limiting, suspicious activity) are useless to a subscriber without it.
func webhookPayload(event model.WebhookEventType, log *model.SecurityAuditLog) model.JSONMap {
	payload := model.JSONMap{
		"event":       string(event),
		"event_id":    log.ID,
		"occurred_at": log.CreatedAt.UTC().Format(time.RFC3339Nano),
		"success":     log.Success,
		"severity":    string(log.Severity),
	}
	if log.UserID != nil {
		payload["user_id"] = *log.UserID
	}
	if log.AppID != nil {
		payload["app_id"] = *log.AppID
	}
	if log.IPAddress != "" {
		payload["ip_address"] = log.IPAddress
	}
	if log.CorrelationID != "" {
		payload["correlation_id"] = log.CorrelationID
	}
	if len(log.Details) > 0 {
		payload["details"] = log.Details
	}
	return payload
}
