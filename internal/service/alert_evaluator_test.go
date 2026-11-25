// Package service — the alert-rule evaluation (#258): enabled rules are
// matched against the security audit log, a met condition records a triggered
// alert, once per group and window, and under enforce sends its notifications.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// alertFakes holds the evaluator's stores in memory; it is the
// AlertEvaluationRepository, and fakeRules and fakeAlerts expose its rules and
// alerts.
type alertFakes struct {
	rules  []model.AlertRule
	alerts []*model.TriggeredAlert
	// counts[eventType][groupBy][group]
	counts  map[string]map[string]map[string]int64
	since   map[uint]time.Time
	failFor uint // CountEventsByGroup fails for this rule's event type
}

type fakeRules struct {
	repository.AlertRuleRepository
	f *alertFakes
}

type fakeAlerts struct {
	repository.TriggeredAlertRepository
	f *alertFakes
}

func (r fakeRules) FindEnabled(context.Context) ([]model.AlertRule, error) {
	var out []model.AlertRule
	for _, r := range r.f.rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s fakeAlerts) Create(_ context.Context, a *model.TriggeredAlert) error {
	a.ID = uint(len(s.f.alerts) + 1)
	s.f.alerts = append(s.f.alerts, a)
	return nil
}

func (s fakeAlerts) Update(context.Context, *model.TriggeredAlert) error { return nil }

func (f *alertFakes) CountEventsByGroup(_ context.Context, eventType string, _ time.Time, groupBy string) (map[string]int64, error) {
	if f.failFor != 0 {
		for _, r := range f.rules {
			if r.ID == f.failFor && r.EventType == eventType {
				return nil, errors.New("db down")
			}
		}
	}
	return f.counts[eventType][groupBy], nil
}

func (f *alertFakes) AlertsForRuleSince(_ context.Context, ruleID uint, since time.Time) ([]model.TriggeredAlert, error) {
	if f.since == nil {
		f.since = map[uint]time.Time{}
	}
	f.since[ruleID] = since
	var out []model.TriggeredAlert
	for _, a := range f.alerts {
		if a.RuleID == ruleID && !a.TriggeredAt.Before(since) {
			out = append(out, *a)
		}
	}
	return out, nil
}

// recordingAudit records the security events logged.
type recordingAudit struct {
	SecurityAuditService
	events []SecurityEvent
}

func (r *recordingAudit) Log(_ context.Context, e SecurityEvent) error {
	r.events = append(r.events, e)
	return nil
}

// recordingMailer records the alert emails sent.
type recordingMailer struct {
	sent []string
	err  error
}

func (m *recordingMailer) SendAlertEmail(to, subject, text string) error {
	m.sent = append(m.sent, to+"|"+subject+"|"+text)
	return m.err
}

var alertNow = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func loginRule(id uint, threshold, window int, groupBy string) model.AlertRule {
	return model.AlertRule{
		ID: id, Name: "Failed logins", EventType: "login_failed", Enabled: true, Severity: model.AlertSeverityError,
		Condition: map[string]interface{}{"threshold": float64(threshold), "window_minutes": float64(window), "group_by": groupBy},
	}
}

func newTestEvaluator(f *alertFakes, mode string) (*AlertEvaluator, *recordingAudit) {
	e := NewAlertEvaluator(fakeRules{f: f}, fakeAlerts{f: f}, f, mode)
	e.now = func() time.Time { return alertNow }
	audit := &recordingAudit{}
	e.SetAuditService(audit)
	return e, audit
}

func TestParseAlertCondition(t *testing.T) {
	ok := []map[string]interface{}{
		{"threshold": 5.0, "window_minutes": 5.0},
		{"threshold": 1.0, "window_minutes": 1440.0, "group_by": "ip_address"},
		{"threshold": 3.0, "window_minutes": 10.0, "group_by": "user_id"},
		{"threshold": 3.0, "window_minutes": 10.0, "group_by": "app_id"},
	}
	for _, c := range ok {
		if _, err := ParseAlertCondition(c); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	bad := []map[string]interface{}{
		nil,
		{"threshold": 0.0, "window_minutes": 5.0},
		{"threshold": 5.0, "window_minutes": 0.0},
		{"threshold": 5.0, "window_minutes": 1441.0},
		{"threshold": 5.0, "window_minutes": 5.0, "group_by": "email"},
		{"threshold": 5.0, "window_minutes": 5.0, "group_by": "ip_address; DROP TABLE users"},
		{"threshold": "five", "window_minutes": 5.0},
	}
	for _, c := range bad {
		if _, err := ParseAlertCondition(c); err == nil {
			t.Errorf("%v: accepted", c)
		}
	}
}

func TestAlertEvaluator_OffEvaluatesNothing(t *testing.T) {
	f := &alertFakes{rules: []model.AlertRule{loginRule(1, 1, 5, "")},
		counts: map[string]map[string]map[string]int64{"login_failed": {"": {"": 10}}}}
	for _, mode := range []string{"off", ""} {
		e, _ := newTestEvaluator(f, mode)
		if n, err := e.EvaluateOnce(context.Background()); n != 0 || err != nil || len(f.alerts) != 0 {
			t.Fatalf("mode %q: %d alerts, err %v", mode, n, err)
		}
	}
}

func TestAlertEvaluator_ObserveRecordsWithoutNotifying(t *testing.T) {
	rule := loginRule(1, 5, 5, "")
	rule.Actions = []string{"email", "webhook"}
	rule.Recipients = []string{"soc@example.test"}
	rule.WebhookURL = "https://hooks.example.test/alert"
	f := &alertFakes{rules: []model.AlertRule{rule},
		counts: map[string]map[string]map[string]int64{"login_failed": {"": {"": 5}}}}
	e, audit := newTestEvaluator(f, AlertRulesModeObserve)
	mailer := &recordingMailer{}
	e.SetMailer(mailer)

	n, err := e.EvaluateOnce(context.Background())
	if n != 1 || err != nil || len(f.alerts) != 1 {
		t.Fatalf("EvaluateOnce = %d, %v; alerts %d", n, err, len(f.alerts))
	}
	a := f.alerts[0]
	if a.RuleID != 1 || a.Severity != model.AlertSeverityError || a.Details["count"] != int64(5) || a.Details["group"] != "" {
		t.Errorf("alert = %+v", a)
	}
	if !strings.Contains(a.Message, "5 login_failed events in 5 min") {
		t.Errorf("message = %q", a.Message)
	}
	if got := f.since[1]; !got.Equal(alertNow.Add(-5 * time.Minute)) {
		t.Errorf("window start = %v, want 5 minutes before now", got)
	}
	notes := a.Details["notifications"].(map[string]interface{})
	if notes["email"] != alertNotifyObserve || notes["webhook"] != alertNotifyObserve || len(mailer.sent) != 0 {
		t.Errorf("observe notified: %v, mails %v", notes, mailer.sent)
	}
	if len(audit.events) != 1 || audit.events[0].EventType != model.SecurityEventAlertTriggered ||
		audit.events[0].Details["rule_id"] != uint(1) || audit.events[0].MinSeverity != model.SecuritySeverityError {
		t.Errorf("audit = %+v", audit.events)
	}
}

func TestAlertEvaluator_BelowThresholdTriggersNothing(t *testing.T) {
	f := &alertFakes{rules: []model.AlertRule{loginRule(1, 5, 5, "")},
		counts: map[string]map[string]map[string]int64{"login_failed": {"": {"": 4}}}}
	e, audit := newTestEvaluator(f, AlertRulesModeObserve)
	if n, _ := e.EvaluateOnce(context.Background()); n != 0 || len(f.alerts) != 0 || len(audit.events) != 0 {
		t.Fatalf("4 of 5 triggered %d alerts", n)
	}
}

// Each group is judged alone, and a group alerted within the window is not
// alerted again; another group still is.
func TestAlertEvaluator_GroupsAndOnceAWindow(t *testing.T) {
	counts := map[string]map[string]map[string]int64{"login_failed": {"ip_address": {"203.0.113.7": 6, "198.51.100.1": 2}}}
	f := &alertFakes{rules: []model.AlertRule{loginRule(1, 5, 10, "ip_address")}, counts: counts}
	e, _ := newTestEvaluator(f, AlertRulesModeObserve)

	if n, err := e.EvaluateOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("first pass = %d, %v", n, err)
	}
	if f.alerts[0].Details["group"] != "203.0.113.7" || !strings.Contains(f.alerts[0].Message, "ip_address 203.0.113.7") {
		t.Errorf("alert = %+v", f.alerts[0])
	}
	if n, _ := e.EvaluateOnce(context.Background()); n != 0 {
		t.Fatalf("the same group was alerted again within the window (%d)", n)
	}
	counts["login_failed"]["ip_address"]["198.51.100.1"] = 5
	if n, _ := e.EvaluateOnce(context.Background()); n != 1 || f.alerts[1].Details["group"] != "198.51.100.1" {
		t.Fatalf("another group reaching the threshold: %d alerts", n)
	}
	// Once the window has passed, the first group can be alerted again.
	e.now = func() time.Time { return alertNow.Add(11 * time.Minute) }
	if n, _ := e.EvaluateOnce(context.Background()); n != 2 {
		t.Fatalf("after the window: %d alerts, want both groups again", n)
	}
}

// A rule that cannot be evaluated is reported, and the others still run.
func TestAlertEvaluator_ABrokenRuleDoesNotStopTheOthers(t *testing.T) {
	broken := loginRule(1, 5, 5, "")
	broken.Condition = map[string]interface{}{"threshold": 0.0}
	failing := loginRule(2, 1, 5, "")
	failing.EventType = "token_revoked"
	good := loginRule(3, 1, 5, "")
	disabled := loginRule(4, 1, 5, "")
	disabled.Enabled = false
	f := &alertFakes{rules: []model.AlertRule{broken, failing, good, disabled}, failFor: 2,
		counts: map[string]map[string]map[string]int64{"login_failed": {"": {"": 3}}, "token_revoked": {"": {"": 3}}}}
	e, _ := newTestEvaluator(f, AlertRulesModeObserve)
	n, err := e.EvaluateOnce(context.Background())
	if n != 1 || len(f.alerts) != 1 || f.alerts[0].RuleID != 3 {
		t.Fatalf("triggered %d (%+v), want only rule 3", n, f.alerts)
	}
	if err == nil || !strings.Contains(err.Error(), "alert rule 1") || !strings.Contains(err.Error(), "alert rule 2") {
		t.Errorf("err = %v, want rules 1 and 2 reported", err)
	}
}

func TestAlertEvaluator_EnforceSendsTheNotifications(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]interface{}
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	rule := loginRule(7, 1, 5, "")
	rule.Actions = []string{"email", "webhook", "slack", "pager"}
	rule.Recipients = []string{"soc@example.test", "oncall@example.test"}
	rule.WebhookURL = srv.URL + "/hook"
	f := &alertFakes{rules: []model.AlertRule{rule},
		counts: map[string]map[string]map[string]int64{"login_failed": {"": {"": 2}}}}
	e, _ := newTestEvaluator(f, AlertRulesModeEnforce)
	e.client = srv.Client()
	mailer := &recordingMailer{}
	e.SetMailer(mailer)

	if n, err := e.EvaluateOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("EvaluateOnce = %d, %v", n, err)
	}
	notes := f.alerts[0].Details["notifications"].(map[string]interface{})
	want := map[string]interface{}{"email": alertNotified, "webhook": alertNotified, "slack": alertNotified, "pager": alertNotifyUnknownAct}
	for k, v := range want {
		if notes[k] != v {
			t.Errorf("notification %s = %v, want %v", k, notes[k], v)
		}
	}
	if len(mailer.sent) != 2 || !strings.HasPrefix(mailer.sent[0], "soc@example.test|[Socrate error] Failed logins|") {
		t.Errorf("mails = %v", mailer.sent)
	}
	if len(bodies) != 2 {
		t.Fatalf("posts = %d, want the webhook and the Slack message", len(bodies))
	}
	var webhook, slack map[string]interface{}
	for _, b := range bodies {
		if b["type"] != nil {
			webhook = b
		} else {
			slack = b
		}
	}
	if webhook["type"] != "socrate.alert_triggered" || webhook["rule_id"] != 7.0 || webhook["severity"] != "error" {
		t.Errorf("webhook body = %v", webhook)
	}
	if text, _ := slack["text"].(string); !strings.HasPrefix(text, "[error] Failed logins: 2 login_failed events") {
		t.Errorf("slack body = %v", slack)
	}

	// A failed send is recorded as such.
	status = http.StatusInternalServerError
	mailer.err = errors.New("smtp down")
	f.alerts = nil
	if n, err := e.EvaluateOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("second pass = %d, %v", n, err)
	}
	notes = f.alerts[0].Details["notifications"].(map[string]interface{})
	if notes["email"] != alertNotifyFailed || notes["webhook"] != alertNotifyFailed || notes["slack"] != alertNotifyFailed {
		t.Errorf("failed sends recorded as %v", notes)
	}
}

func TestAlertEvaluator_EnforceWithoutATarget(t *testing.T) {
	rule := loginRule(1, 1, 5, "")
	rule.Actions = []string{"email", "webhook"}
	f := &alertFakes{rules: []model.AlertRule{rule},
		counts: map[string]map[string]map[string]int64{"login_failed": {"": {"": 1}}}}
	e, _ := newTestEvaluator(f, AlertRulesModeEnforce)
	if _, err := e.EvaluateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	notes := f.alerts[0].Details["notifications"].(map[string]interface{})
	if notes["email"] != alertNotifyNoMailer || notes["webhook"] != alertNotifyNoTarget {
		t.Errorf("notifications = %v", notes)
	}

	// With a mailer but no recipient, and a webhook_url that is not https.
	rule.WebhookURL = "http://hooks.example.test/alert"
	f2 := &alertFakes{rules: []model.AlertRule{rule}, counts: f.counts}
	e2, _ := newTestEvaluator(f2, AlertRulesModeEnforce)
	e2.SetMailer(&recordingMailer{})
	if _, err := e2.EvaluateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	notes = f2.alerts[0].Details["notifications"].(map[string]interface{})
	if notes["email"] != alertNotifyNoTarget || notes["webhook"] != alertNotifyFailed {
		t.Errorf("notifications = %v", notes)
	}
}

func TestAlertSeverity_DefaultsToWarning(t *testing.T) {
	for in, want := range map[model.AlertSeverity]model.AlertSeverity{
		"critical": "critical", "error": "error", "warning": "warning", "": "warning", "info": "warning",
	} {
		if got := alertSeverity(in); got != want {
			t.Errorf("alertSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
