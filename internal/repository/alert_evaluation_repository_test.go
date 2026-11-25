package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// #258: the alert-rule evaluation counts a rule's events in its window, per
// group, and finds the alerts the rule already triggered.
func TestAlertEvaluationRepository(t *testing.T) {
	db := auditScratchDB(t)
	if err := db.AutoMigrate(&model.User{}, &model.App{}, &model.SecurityAuditLog{}, &model.AlertRule{}, &model.TriggeredAlert{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	u1, u2, a1 := uint(11), uint(12), uint(21)
	for _, id := range []uint{u1, u2} {
		if err := db.Create(&model.User{ID: id, Email: fmt.Sprintf("u%d@example.test", id), Name: "u"}).Error; err != nil {
			t.Fatalf("user %d: %v", id, err)
		}
	}
	events := []model.SecurityAuditLog{
		{EventType: "login_failed", IPAddress: "203.0.113.7", UserID: &u1, AppID: &a1, CreatedAt: now.Add(-1 * time.Minute)},
		{EventType: "login_failed", IPAddress: "203.0.113.7", UserID: &u1, CreatedAt: now.Add(-2 * time.Minute)},
		{EventType: "login_failed", IPAddress: "198.51.100.1", UserID: &u2, CreatedAt: now.Add(-3 * time.Minute)},
		{EventType: "login_failed", IPAddress: "", CreatedAt: now.Add(-4 * time.Minute)},
		// Outside the window, and another event type: not counted.
		{EventType: "login_failed", IPAddress: "203.0.113.7", UserID: &u1, CreatedAt: now.Add(-20 * time.Minute)},
		{EventType: "token_revoked", IPAddress: "203.0.113.7", UserID: &u1, CreatedAt: now.Add(-1 * time.Minute)},
	}
	for i := range events {
		events[i].Severity = model.SecuritySeverityWarning
		if err := db.Create(&events[i]).Error; err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	repo := repository.NewAlertEvaluationRepository(db)
	since := now.Add(-10 * time.Minute)
	for groupBy, want := range map[string]map[string]int64{
		"":           {"": 4},
		"ip_address": {"203.0.113.7": 2, "198.51.100.1": 1},
		"user_id":    {"11": 2, "12": 1},
		"app_id":     {"21": 1},
	} {
		got, err := repo.CountEventsByGroup(ctx, "login_failed", since, groupBy)
		if err != nil {
			t.Fatalf("group_by %q: %v", groupBy, err)
		}
		if len(got) != len(want) {
			t.Errorf("group_by %q = %v, want %v", groupBy, got, want)
			continue
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("group_by %q = %v, want %v", groupBy, got, want)
			}
		}
	}
	if _, err := repo.CountEventsByGroup(ctx, "login_failed", since, "email"); err == nil {
		t.Error("an unsupported group_by was queried")
	}

	rule := &model.AlertRule{Name: "r", EventType: "login_failed", Severity: model.AlertSeverityWarning,
		Condition: map[string]interface{}{"threshold": 1}, Actions: []string{}}
	if err := db.Create(rule).Error; err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(-30 * time.Minute), now.Add(-2 * time.Minute)} {
		if err := db.Create(&model.TriggeredAlert{RuleID: rule.ID, Severity: model.AlertSeverityWarning, Message: "m",
			Details: map[string]interface{}{"group": ""}, TriggeredAt: at}).Error; err != nil {
			t.Fatal(err)
		}
	}
	recent, err := repo.AlertsForRuleSince(ctx, rule.ID, since)
	if err != nil || len(recent) != 1 || recent[0].Details["group"] != "" {
		t.Fatalf("AlertsForRuleSince = %+v, %v; want the one within the window", recent, err)
	}
}
