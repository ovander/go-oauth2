package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/ssrf"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// ALERT_RULES_MODE values (#258).
const (
	AlertRulesModeObserve = "observe"
	AlertRulesModeEnforce = "enforce"
)

// Limits of an alert rule's condition.
const (
	alertMaxWindowMinutes = 24 * 60
	alertSendTimeout      = 10 * time.Second
)

// Notification outcomes recorded in a triggered alert's details.
const (
	alertNotified         = "sent"
	alertNotifyFailed     = "failed"
	alertNotifyObserve    = "not sent (ALERT_RULES_MODE=observe)"
	alertNotifyNoTarget   = "not sent (no recipient or webhook_url)"
	alertNotifyNoMailer   = "not sent (email is not configured)"
	alertNotifyUnknownAct = "not sent (unknown action)"
)

// AlertMailer sends an alert email. The SMTP email service implements it.
type AlertMailer interface {
	SendAlertEmail(to, subject, text string) error
}

// ParseAlertCondition reads an alert rule's condition: threshold (at least
// 1), window_minutes (1 to 1440) and group_by ("", ip_address, user_id or
// app_id).
func ParseAlertCondition(raw map[string]interface{}) (model.AlertCondition, error) {
	var cond model.AlertCondition
	b, err := json.Marshal(raw)
	if err != nil {
		return cond, fmt.Errorf("condition: %w", err)
	}
	if err := json.Unmarshal(b, &cond); err != nil {
		return cond, fmt.Errorf("condition: %w", err)
	}
	switch {
	case cond.Threshold < 1:
		return cond, errors.New("condition: threshold must be at least 1")
	case cond.WindowMinutes < 1 || cond.WindowMinutes > alertMaxWindowMinutes:
		return cond, fmt.Errorf("condition: window_minutes must be between 1 and %d", alertMaxWindowMinutes)
	case !repository.ValidAlertGroupBy(cond.GroupBy):
		return cond, fmt.Errorf("condition: unsupported group_by %q", cond.GroupBy)
	}
	return cond, nil
}

// AlertEvaluator evaluates the enabled alert rules against the security audit
// log (#258). Each pass counts, for every enabled rule, the events of its
// event_type in its window, per group of its group_by; a group whose count
// reaches the threshold triggers an alert, unless the rule already triggered
// one for that group within the window. Under ALERT_RULES_MODE=enforce the
// rule's notifications are then sent; under observe they are not.
type AlertEvaluator struct {
	rules  repository.AlertRuleRepository
	alerts repository.TriggeredAlertRepository
	events repository.AlertEvaluationRepository
	audit  SecurityAuditService
	mailer AlertMailer
	client *http.Client
	mode   string
	now    func() time.Time
}

// NewAlertEvaluator returns an evaluator for ALERT_RULES_MODE mode. Webhook
// and Slack notifications go through the SSRF-guarded HTTP client.
func NewAlertEvaluator(rules repository.AlertRuleRepository, alerts repository.TriggeredAlertRepository,
	events repository.AlertEvaluationRepository, mode string) *AlertEvaluator {
	return &AlertEvaluator{
		rules: rules, alerts: alerts, events: events, mode: mode,
		client: ssrf.NewHTTPClient(alertSendTimeout),
		now:    time.Now,
	}
}

// SetAuditService records each triggered alert as an alert_triggered security
// event. Nil records none.
func (e *AlertEvaluator) SetAuditService(audit SecurityAuditService) { e.audit = audit }

// SetMailer sends the email notifications. Nil (no SMTP) leaves them unsent,
// which the alert records.
func (e *AlertEvaluator) SetMailer(mailer AlertMailer) { e.mailer = mailer }

// EvaluateOnce runs one pass over the enabled rules and returns how many
// alerts it triggered. A rule that cannot be evaluated (an invalid condition,
// a failed query) is skipped and reported in the error; the others still run.
func (e *AlertEvaluator) EvaluateOnce(ctx context.Context) (int, error) {
	if e.mode != AlertRulesModeObserve && e.mode != AlertRulesModeEnforce {
		return 0, nil
	}
	rules, err := e.rules.FindEnabled(ctx)
	if err != nil {
		return 0, fmt.Errorf("alert rules: %w", err)
	}
	triggered := 0
	var errs []error
	for i := range rules {
		n, err := e.evaluateRule(ctx, &rules[i])
		triggered += n
		if err != nil {
			errs = append(errs, fmt.Errorf("alert rule %d: %w", rules[i].ID, err))
		}
	}
	return triggered, errors.Join(errs...)
}

func (e *AlertEvaluator) evaluateRule(ctx context.Context, rule *model.AlertRule) (int, error) {
	cond, err := ParseAlertCondition(rule.Condition)
	if err != nil {
		return 0, err
	}
	now := e.now()
	since := now.Add(-time.Duration(cond.WindowMinutes) * time.Minute)
	counts, err := e.events.CountEventsByGroup(ctx, rule.EventType, since, cond.GroupBy)
	if err != nil {
		return 0, err
	}
	recent, err := e.events.AlertsForRuleSince(ctx, rule.ID, since)
	if err != nil {
		return 0, err
	}
	alerted := make(map[string]bool, len(recent))
	for _, a := range recent {
		if g, ok := a.Details["group"].(string); ok {
			alerted[g] = true
		}
	}
	triggered := 0
	for group, count := range counts {
		if count < int64(cond.Threshold) || alerted[group] {
			continue
		}
		if err := e.trigger(ctx, rule, cond, group, count, now); err != nil {
			return triggered, err
		}
		triggered++
	}
	return triggered, nil
}

func (e *AlertEvaluator) trigger(ctx context.Context, rule *model.AlertRule, cond model.AlertCondition, group string, count int64, now time.Time) error {
	severity := alertSeverity(rule.Severity)
	msg := fmt.Sprintf("%s: %d %s events in %d min", rule.Name, count, rule.EventType, cond.WindowMinutes)
	if cond.GroupBy != "" {
		msg += fmt.Sprintf(" (%s %s)", cond.GroupBy, group)
	}
	alert := &model.TriggeredAlert{
		RuleID:   rule.ID,
		Severity: severity,
		Message:  msg,
		Details: map[string]interface{}{
			"event_type":     rule.EventType,
			"group_by":       cond.GroupBy,
			"group":          group,
			"count":          count,
			"threshold":      cond.Threshold,
			"window_minutes": cond.WindowMinutes,
		},
		TriggeredAt: now,
	}
	if err := e.alerts.Create(ctx, alert); err != nil {
		return fmt.Errorf("record alert: %w", err)
	}
	e.auditTriggered(ctx, rule, alert)

	alert.Details["notifications"] = e.notify(ctx, rule, alert)
	if err := e.alerts.Update(ctx, alert); err != nil {
		// The alert is recorded; only the notification outcome is missing.
		logger.WithFields(logger.Fields{"alert_id": alert.ID, "error": err.Error()}).
			Warn("alert rules: could not record the notification outcome")
	}
	return nil
}

func (e *AlertEvaluator) auditTriggered(ctx context.Context, rule *model.AlertRule, alert *model.TriggeredAlert) {
	if e.audit == nil {
		return
	}
	details := map[string]interface{}{"alert_id": alert.ID, "rule_id": rule.ID, "rule_name": rule.Name, "mode": e.mode}
	for k, v := range alert.Details {
		details[k] = v
	}
	if err := e.audit.Log(ctx, SecurityEvent{
		EventType:   model.SecurityEventAlertTriggered,
		Success:     true,
		Details:     details,
		MinSeverity: model.SecuritySeverity(alert.Severity),
	}); err != nil {
		logger.WithFields(logger.Fields{"alert_id": alert.ID, "error": err.Error()}).
			Warn("alert rules: could not audit a triggered alert")
	}
}

// notify sends the rule's notifications under enforce and returns the outcome
// of each action.
func (e *AlertEvaluator) notify(ctx context.Context, rule *model.AlertRule, alert *model.TriggeredAlert) map[string]interface{} {
	outcome := make(map[string]interface{}, len(rule.Actions))
	for _, action := range rule.Actions {
		if e.mode != AlertRulesModeEnforce {
			outcome[action] = alertNotifyObserve
			continue
		}
		var err error
		switch model.AlertAction(action) {
		case model.AlertActionEmail:
			if e.mailer == nil {
				outcome[action] = alertNotifyNoMailer
				continue
			}
			if len(rule.Recipients) == 0 {
				outcome[action] = alertNotifyNoTarget
				continue
			}
			err = e.sendEmail(rule, alert)
		case model.AlertActionWebhook, model.AlertActionSlack:
			if rule.WebhookURL == "" {
				outcome[action] = alertNotifyNoTarget
				continue
			}
			err = e.post(ctx, rule, alert, model.AlertAction(action))
		default:
			outcome[action] = alertNotifyUnknownAct
			continue
		}
		if err != nil {
			outcome[action] = alertNotifyFailed
			logger.WithFields(logger.Fields{"alert_id": alert.ID, "rule_id": rule.ID, "action": action, "error": err.Error()}).
				Warn("alert rules: notification failed")
			continue
		}
		outcome[action] = alertNotified
	}
	return outcome
}

func (e *AlertEvaluator) sendEmail(rule *model.AlertRule, alert *model.TriggeredAlert) error {
	subject := fmt.Sprintf("[Socrate %s] %s", alert.Severity, rule.Name)
	text := fmt.Sprintf("%s\n\nRule: %s (id %d)\nSeverity: %s\nTriggered at: %s\n",
		alert.Message, rule.Name, rule.ID, alert.Severity, alert.TriggeredAt.UTC().Format(time.RFC3339))
	var errs []error
	for _, to := range rule.Recipients {
		if err := e.mailer.SendAlertEmail(to, subject, text); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// post sends a webhook (a JSON description of the alert) or a Slack message
// (its text) to the rule's webhook_url, an https URL to a public address.
func (e *AlertEvaluator) post(ctx context.Context, rule *model.AlertRule, alert *model.TriggeredAlert, action model.AlertAction) error {
	if _, err := ssrf.ParseURL(rule.WebhookURL); err != nil {
		return fmt.Errorf("webhook_url: %w", err)
	}
	var payload interface{} = map[string]interface{}{"text": fmt.Sprintf("[%s] %s", alert.Severity, alert.Message)}
	if action == model.AlertActionWebhook {
		payload = map[string]interface{}{
			"type":         "socrate.alert_triggered",
			"alert_id":     alert.ID,
			"rule_id":      rule.ID,
			"rule_name":    rule.Name,
			"severity":     alert.Severity,
			"message":      alert.Message,
			"details":      alert.Details,
			"triggered_at": alert.TriggeredAt.UTC().Format(time.RFC3339),
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, alertSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rule.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook answered %d", resp.StatusCode)
	}
	return nil
}

// alertSeverity is a rule's severity, warning when it is not one of the three.
func alertSeverity(s model.AlertSeverity) model.AlertSeverity {
	switch s {
	case model.AlertSeverityWarning, model.AlertSeverityError, model.AlertSeverityCritical:
		return s
	}
	return model.AlertSeverityWarning
}
