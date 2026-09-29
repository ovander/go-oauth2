package service

import (
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// stubSubs stands in for the webhook service's routing cache.
type stubSubs struct{ subs []model.WebhookSubscription }

func (s stubSubs) Subscriptions() []model.WebhookSubscription { return s.subs }

func outboxWith(enabled bool, subs ...model.WebhookSubscription) *WebhookOutbox {
	return &WebhookOutbox{subs: stubSubs{subs: subs}, enabled: enabled}
}

func auditRow(eventType model.SecurityEventType, appID *uint) *model.SecurityAuditLog {
	uid := uint(7)
	return &model.SecurityAuditLog{
		ID:            42,
		UserID:        &uid,
		AppID:         appID,
		EventType:     eventType,
		Severity:      model.SecuritySeverityInfo,
		IPAddress:     "203.0.113.9",
		CorrelationID: "corr-1",
		Success:       true,
		Details:       map[string]interface{}{"method": "password"},
		CreatedAt:     time.Now(),
	}
}

// The kill switch: with WEBHOOKS_MODE off nothing is enqueued, whatever is
// subscribed.
func TestOutbox_DisabledEnqueuesNothing(t *testing.T) {
	o := outboxWith(false, model.WebhookSubscription{
		ID: 1, Active: true, EventTypes: model.StringArray{model.WebhookEventWildcard},
	})
	if got := o.DeliveriesFor(auditRow(model.SecurityEventLoginSuccess, nil)); len(got) != 0 {
		t.Fatalf("disabled outbox produced %d deliveries", len(got))
	}
}

// An audit event outside the catalogue produces no delivery, so internal
// bookkeeping never reaches a subscriber.
func TestOutbox_UncataloguedEventEnqueuesNothing(t *testing.T) {
	o := outboxWith(true, model.WebhookSubscription{
		ID: 1, Active: true, EventTypes: model.StringArray{model.WebhookEventWildcard},
	})
	for _, e := range []model.SecurityEventType{
		model.SecurityEventTokenIssued,
		model.SecurityEventTokenRefreshed,
		model.SecurityEventLogout,
	} {
		if got := o.DeliveriesFor(auditRow(e, nil)); len(got) != 0 {
			t.Errorf("%s produced %d deliveries; it is not in the catalogue", e, len(got))
		}
	}
}

// One delivery per matching subscription, none for the others.
func TestOutbox_RoutesToMatchingSubscriptions(t *testing.T) {
	appA := uint(1)
	appB := uint(2)

	o := outboxWith(true,
		model.WebhookSubscription{ID: 1, Active: true, EventTypes: model.StringArray{model.WebhookEventWildcard}},
		model.WebhookSubscription{ID: 2, Active: true, EventTypes: model.StringArray{"login.succeeded"}},
		model.WebhookSubscription{ID: 3, Active: true, EventTypes: model.StringArray{"user.created"}},
		model.WebhookSubscription{ID: 4, Active: false, EventTypes: model.StringArray{model.WebhookEventWildcard}},
		model.WebhookSubscription{ID: 5, Active: true, AppID: &appB, EventTypes: model.StringArray{model.WebhookEventWildcard}},
		model.WebhookSubscription{ID: 6, Active: true, AppID: &appA, EventTypes: model.StringArray{"login.succeeded"}},
	)

	got := o.DeliveriesFor(auditRow(model.SecurityEventLoginSuccess, &appA))

	want := map[uint]bool{1: true, 2: true, 6: true}
	if len(got) != len(want) {
		t.Fatalf("got %d deliveries, want %d: %+v", len(got), len(want), got)
	}
	for _, d := range got {
		if !want[d.SubscriptionID] {
			t.Errorf("delivery for subscription %d should not have been enqueued", d.SubscriptionID)
		}
		if d.Status != model.WebhookDeliveryPending {
			t.Errorf("delivery status = %q, want pending", d.Status)
		}
		if d.EventType != model.WebhookLoginSucceeded {
			t.Errorf("delivery event = %q, want login.succeeded", d.EventType)
		}
		if d.AuditLogID == nil || *d.AuditLogID != 42 {
			t.Errorf("delivery is not linked to its audit row: %v", d.AuditLogID)
		}
		if d.Attempts != 0 || d.DeliveredAt != nil {
			t.Errorf("a fresh delivery must be unattempted and undelivered: %+v", d)
		}
	}
}

// The payload carries what a subscriber needs and nothing more — in particular
// not the audit row's integrity hashes or the user agent.
func TestOutbox_PayloadShape(t *testing.T) {
	appID := uint(3)
	log := auditRow(model.SecurityEventClientSecretRotated, &appID)
	log.UserAgent = "curl/8.0"
	log.RowHash = "deadbeef"
	log.PrevHash = "cafebabe"

	o := outboxWith(true, model.WebhookSubscription{
		ID: 1, Active: true, EventTypes: model.StringArray{model.WebhookEventWildcard},
	})
	got := o.DeliveriesFor(log)
	if len(got) != 1 {
		t.Fatalf("got %d deliveries, want 1", len(got))
	}
	p := got[0].Payload

	if p["event"] != string(model.WebhookClientSecretRotated) {
		t.Errorf("event = %v", p["event"])
	}
	if p["event_id"] != uint(42) {
		t.Errorf("event_id = %v, want 42", p["event_id"])
	}
	if p["user_id"] != uint(7) || p["app_id"] != uint(3) {
		t.Errorf("user_id/app_id = %v/%v", p["user_id"], p["app_id"])
	}
	if p["ip_address"] != "203.0.113.9" {
		t.Errorf("ip_address = %v", p["ip_address"])
	}
	if p["correlation_id"] != "corr-1" {
		t.Errorf("correlation_id = %v", p["correlation_id"])
	}
	if p["success"] != true || p["severity"] == "" {
		t.Errorf("success/severity = %v/%v", p["success"], p["severity"])
	}
	if _, ok := p["occurred_at"].(string); !ok {
		t.Errorf("occurred_at is missing or not a string: %v", p["occurred_at"])
	}
	if p["details"] == nil {
		t.Error("details were dropped")
	}

	for _, leaked := range []string{"row_hash", "prev_hash", "user_agent"} {
		if _, present := p[leaked]; present {
			t.Errorf("payload carries %q, which subscribers must not receive", leaked)
		}
	}
}

// Every subscription for one event shares the same frozen payload, so a retry
// re-sends identical bytes and the signature stays reproducible.
func TestOutbox_PayloadIsSharedAndFrozen(t *testing.T) {
	o := outboxWith(true,
		model.WebhookSubscription{ID: 1, Active: true, EventTypes: model.StringArray{model.WebhookEventWildcard}},
		model.WebhookSubscription{ID: 2, Active: true, EventTypes: model.StringArray{model.WebhookEventWildcard}},
	)
	got := o.DeliveriesFor(auditRow(model.SecurityEventUserRegistered, nil))
	if len(got) != 2 {
		t.Fatalf("got %d deliveries, want 2", len(got))
	}
	if got[0].Payload["event_id"] != got[1].Payload["event_id"] {
		t.Fatal("the two deliveries carry different payloads")
	}
}

// A nil outbox and a nil audit row are both no-ops rather than panics.
func TestOutbox_NilSafe(t *testing.T) {
	var o *WebhookOutbox
	if got := o.DeliveriesFor(auditRow(model.SecurityEventLoginSuccess, nil)); got != nil {
		t.Error("a nil outbox produced deliveries")
	}
	live := outboxWith(true, model.WebhookSubscription{ID: 1, Active: true, EventTypes: model.StringArray{"*"}})
	if got := live.DeliveriesFor(nil); got != nil {
		t.Error("a nil audit row produced deliveries")
	}
}

// With no subscriptions registered — the state of every deployment until an
// operator adds one — the outbox does nothing even when enabled.
func TestOutbox_NoSubscriptions(t *testing.T) {
	o := outboxWith(true)
	if got := o.DeliveriesFor(auditRow(model.SecurityEventLoginSuccess, nil)); len(got) != 0 {
		t.Fatalf("produced %d deliveries with no subscriptions", len(got))
	}
}
