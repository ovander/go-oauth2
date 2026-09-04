package model

import (
	"testing"
)

// The catalogue is an allow-list: an internal audit event that is not mapped
// produces no webhook, so adding a SecurityEventType never starts leaking to
// subscribers by accident.
func TestWebhookEventForAudit_IsAnAllowList(t *testing.T) {
	if got, ok := WebhookEventForAudit(SecurityEventUserRegistered); !ok || got != WebhookUserCreated {
		t.Errorf("user_registered → %q (ok=%v), want user.created", got, ok)
	}
	if got, ok := WebhookEventForAudit(SecurityEventClientSecretRotated); !ok || got != WebhookClientSecretRotated {
		t.Errorf("client_secret_rotated → %q (ok=%v), want client.secret_rotated", got, ok)
	}

	// Deliberately unmapped: internal token bookkeeping a subscriber has no
	// business seeing on every request.
	unmapped := []SecurityEventType{
		SecurityEventTokenIssued,
		SecurityEventTokenRefreshed,
		SecurityEventAuthCodeIssued,
		SecurityEventLogout,
		"a_type_that_does_not_exist",
	}
	for _, e := range unmapped {
		if got, ok := WebhookEventForAudit(e); ok {
			t.Errorf("%s is mapped to %q; it should not be in the catalogue", e, got)
		}
	}
}

func TestWebhookEventCatalogue(t *testing.T) {
	events := WebhookEventCatalogue()
	if len(events) == 0 {
		t.Fatal("catalogue is empty")
	}
	for i := 1; i < len(events); i++ {
		if events[i-1] > events[i] {
			t.Fatalf("catalogue is not sorted: %q before %q", events[i-1], events[i])
		}
	}
	for _, name := range events {
		if !IsKnownWebhookEvent(name) {
			t.Errorf("catalogue lists %q but IsKnownWebhookEvent says no", name)
		}
	}
	if IsKnownWebhookEvent("user.exfiltrated") {
		t.Error("IsKnownWebhookEvent accepted a name outside the catalogue")
	}
	if IsKnownWebhookEvent(WebhookEventWildcard) {
		t.Error("the wildcard is not itself a catalogue entry")
	}
}

func TestNormalizeEventFilter(t *testing.T) {
	got := NormalizeEventFilter([]string{" user.created ", "login.failed", "user.created", ""})
	if len(got) != 2 || got[0] != "login.failed" || got[1] != "user.created" {
		t.Fatalf("NormalizeEventFilter = %v, want [login.failed user.created]", got)
	}

	// The wildcard swallows the rest, so a filter can never be read as narrower
	// than it is.
	if got := NormalizeEventFilter([]string{"user.created", "*"}); len(got) != 1 || got[0] != "*" {
		t.Fatalf("wildcard filter = %v, want [*]", got)
	}
	if got := NormalizeEventFilter(nil); len(got) != 0 {
		t.Fatalf("nil filter = %v, want empty", got)
	}
}

// Matching is the routing decision, so the app scoping and the active flag both
// have to hold.
func TestWebhookSubscription_Matches(t *testing.T) {
	appA := uint(1)
	appB := uint(2)

	global := &WebhookSubscription{Active: true, EventTypes: StringArray{"user.created"}}
	if !global.Matches(WebhookUserCreated, &appA) {
		t.Error("a global subscription must match an app-scoped event")
	}
	if !global.Matches(WebhookUserCreated, nil) {
		t.Error("a global subscription must match an event with no app")
	}
	if global.Matches(WebhookLoginFailed, &appA) {
		t.Error("matched an event outside the filter")
	}

	scoped := &WebhookSubscription{Active: true, AppID: &appA, EventTypes: StringArray{"user.created"}}
	if !scoped.Matches(WebhookUserCreated, &appA) {
		t.Error("an app-scoped subscription must match its own app's event")
	}
	if scoped.Matches(WebhookUserCreated, &appB) {
		t.Error("an app-scoped subscription leaked another app's event")
	}
	if scoped.Matches(WebhookUserCreated, nil) {
		t.Error("an app-scoped subscription matched an event with no app")
	}

	wildcard := &WebhookSubscription{Active: true, EventTypes: StringArray{WebhookEventWildcard}}
	if !wildcard.Matches(WebhookLoginFailed, nil) || !wildcard.Matches(WebhookClientDeleted, &appA) {
		t.Error("the wildcard must match every event")
	}

	inactive := &WebhookSubscription{Active: false, EventTypes: StringArray{WebhookEventWildcard}}
	if inactive.Matches(WebhookUserCreated, nil) {
		t.Error("an inactive subscription must match nothing")
	}

	empty := &WebhookSubscription{Active: true}
	if empty.Matches(WebhookUserCreated, nil) {
		t.Error("a subscription with no filter must match nothing")
	}
}
