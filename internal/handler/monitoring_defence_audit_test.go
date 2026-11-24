package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// defenceBlocks keeps blocks in memory.
type defenceBlocks struct {
	repository.BlockedIPRepository
	rows    map[uint]*model.BlockedIP
	deletes int
	findErr error // when set, FindByID fails with it (an unavailable database)
}

func (r *defenceBlocks) IsBlocked(context.Context, string) (bool, error) { return false, nil }
func (r *defenceBlocks) Create(_ context.Context, b *model.BlockedIP) error {
	b.ID = uint(len(r.rows) + 100)
	r.rows[b.ID] = b
	return nil
}
func (r *defenceBlocks) FindByID(_ context.Context, id uint) (*model.BlockedIP, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	if b, ok := r.rows[id]; ok {
		return b, nil
	}
	return nil, gorm.ErrRecordNotFound
}
func (r *defenceBlocks) Delete(_ context.Context, id uint) error {
	r.deletes++
	delete(r.rows, id)
	return nil
}

// defenceRules keeps alert rules in memory.
type defenceRules struct {
	repository.AlertRuleRepository
	rows    map[uint]*model.AlertRule
	deletes int
	findErr error // when set, FindByID fails with it (an unavailable database)
}

func (r *defenceRules) Create(_ context.Context, rule *model.AlertRule) error {
	rule.ID = uint(len(r.rows) + 1)
	cp := *rule
	r.rows[rule.ID] = &cp
	return nil
}
func (r *defenceRules) FindByID(_ context.Context, id uint) (*model.AlertRule, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	if rule, ok := r.rows[id]; ok {
		cp := *rule
		return &cp, nil
	}
	return nil, gorm.ErrRecordNotFound
}
func (r *defenceRules) Update(_ context.Context, rule *model.AlertRule) error {
	cp := *rule
	r.rows[rule.ID] = &cp
	return nil
}
func (r *defenceRules) Delete(_ context.Context, id uint) error {
	r.deletes++
	delete(r.rows, id)
	return nil
}

func newDefenceHandler() (*MonitoringHandler, *defenceBlocks, *defenceRules, *captureAuditService) {
	blocks := &defenceBlocks{rows: map[uint]*model.BlockedIP{}}
	rules := &defenceRules{rows: map[uint]*model.AlertRule{}}
	audit := &captureAuditService{}
	h := &MonitoringHandler{blockedIPRepo: blocks, alertRuleRepo: rules}
	h.SetSecurityAuditService(audit)
	return h, blocks, rules, audit
}

// call runs handler fn as admin 7, with {id} set when id is not empty.
func call(fn http.HandlerFunc, method, id, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/admin/x", bytes.NewBufferString(body))
	ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, uint(7))
	if id != "" {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", id)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rc)
	}
	rr := httptest.NewRecorder()
	fn(rr, r.WithContext(ctx))
	return rr
}

// A manual block, and its removal, are security events naming the admin and
// the block; lifting a block that does not exist is a 404 with no event.
func TestDefenceAudit_BlockAndUnblock(t *testing.T) {
	h, blocks, _, audit := newDefenceHandler()

	if rr := call(h.BlockIP, http.MethodPost, "", `{"ip_address":"198.51.100.9","reason":"scanner","duration_hours":2}`); rr.Code != http.StatusCreated {
		t.Fatalf("block: %d %s", rr.Code, rr.Body.String())
	}
	ev := findEvent(audit, model.SecurityEventIPBlocked)
	if ev == nil || ev.UserID == nil || *ev.UserID != 7 || ev.Details["ip_address"] != "198.51.100.9" || ev.Details["reason"] != "scanner" || ev.Details["expires_at"] == nil {
		t.Fatalf("ip_blocked event: %+v", ev)
	}
	id := ev.Details["block_id"].(uint)

	if rr := call(h.UnblockIP, http.MethodDelete, "999", ""); rr.Code != http.StatusNotFound || blocks.deletes != 0 {
		t.Fatalf("unknown block: %d, deletes %d", rr.Code, blocks.deletes)
	}
	if findEvent(audit, model.SecurityEventIPUnblocked) != nil {
		t.Fatal("an unknown block was audited as lifted")
	}
	if rr := call(h.UnblockIP, http.MethodDelete, itoaUint(id), ""); rr.Code != http.StatusNoContent {
		t.Fatalf("unblock: %d", rr.Code)
	}
	ev = findEvent(audit, model.SecurityEventIPUnblocked)
	if ev == nil || *ev.UserID != 7 || ev.Details["ip_address"] != "198.51.100.9" || ev.Details["reason"] != "scanner" || ev.Details["blocked_by"] != uint(7) {
		t.Fatalf("ip_unblocked event: %+v", ev)
	}
}

// Alert-rule changes are recorded with their values, old and new on an
// update; the webhook URL appears only as its host.
func TestDefenceAudit_AlertRules(t *testing.T) {
	h, _, rules, audit := newDefenceHandler()

	const secretHook = "https://hooks.example.com/services/T000/B000/s3cr3t-token"
	body := `{"name":"Brute force","event_type":"login_failed","severity":"high","actions":["email"],"recipients":["soc@example.com"],"webhook_url":"` + secretHook + `"}`
	if rr := call(h.CreateAlertRule, http.MethodPost, "", body); rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	created := findEvent(audit, model.SecurityEventAlertRuleCreated)
	if created == nil || *created.UserID != 7 {
		t.Fatalf("alert_rule_created: %+v", created)
	}
	if got := created.Details["rule"].(map[string]interface{}); got["name"] != "Brute force" || got["webhook_host"] != "hooks.example.com" {
		t.Fatalf("created rule values: %+v", got)
	}

	if rr := call(h.UpdateAlertRule, http.MethodPut, "1", `{"enabled":false,"webhook_url":"https://other.example.com/x/y"}`); rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	updated := findEvent(audit, model.SecurityEventAlertRuleUpdated)
	if updated == nil {
		t.Fatal("no alert_rule_updated event")
	}
	before := updated.Details["before"].(map[string]interface{})
	after := updated.Details["after"].(map[string]interface{})
	if before["enabled"] != true || after["enabled"] != false || updated.Details["webhook_url_changed"] != true || after["webhook_host"] != "other.example.com" {
		t.Fatalf("update recorded before %+v after %+v changed %v", before, after, updated.Details["webhook_url_changed"])
	}

	if rr := call(h.DeleteAlertRule, http.MethodDelete, "99", ""); rr.Code != http.StatusNotFound || rules.deletes != 0 {
		t.Fatalf("unknown rule: %d, deletes %d", rr.Code, rules.deletes)
	}
	if rr := call(h.DeleteAlertRule, http.MethodDelete, "1", ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rr.Code)
	}
	deleted := findEvent(audit, model.SecurityEventAlertRuleDeleted)
	if deleted == nil || deleted.Details["rule"].(map[string]interface{})["name"] != "Brute force" {
		t.Fatalf("alert_rule_deleted: %+v", deleted)
	}

	// The webhook URL's path (its secret) is never recorded.
	all, _ := json.Marshal(audit.events)
	if strings.Contains(string(all), "s3cr3t-token") || strings.Contains(string(all), "/x/y") {
		t.Fatalf("a webhook URL path reached the audit: %s", all)
	}
}

func itoaUint(u uint) string {
	b, _ := json.Marshal(u)
	return string(b)
}

// Lifting a block or changing or deleting an alert rule is a warning.
func TestDefenceAudit_Severities(t *testing.T) {
	for ev, want := range map[model.SecurityEventType]model.SecuritySeverity{
		model.SecurityEventIPBlocked:        model.SecuritySeverityWarning,
		model.SecurityEventIPUnblocked:      model.SecuritySeverityWarning,
		model.SecurityEventAlertRuleCreated: model.SecuritySeverityInfo,
		model.SecurityEventAlertRuleUpdated: model.SecuritySeverityWarning,
		model.SecurityEventAlertRuleDeleted: model.SecuritySeverityWarning,
	} {
		if got := model.GetSeverityForEvent(ev, true); got != want {
			t.Errorf("%s: %s, want %s", ev, got, want)
		}
	}
}

// A failed lookup that is not "not found" (an unavailable database) is a
// 500, not a 404, and nothing is deleted or recorded.
func TestDefenceAudit_LookupFailureIsNotANotFound(t *testing.T) {
	h, blocks, rules, audit := newDefenceHandler()
	blocks.findErr = errors.New("connection refused")
	rules.findErr = errors.New("connection refused")
	for name, rr := range map[string]*httptest.ResponseRecorder{
		"unblock":     call(h.UnblockIP, http.MethodDelete, "1", ""),
		"delete rule": call(h.DeleteAlertRule, http.MethodDelete, "1", ""),
		"update rule": call(h.UpdateAlertRule, http.MethodPut, "1", `{"enabled":false}`),
	} {
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("%s with the database down: %d, want 500", name, rr.Code)
		}
	}
	if blocks.deletes != 0 || rules.deletes != 0 || len(audit.events) != 0 {
		t.Fatalf("deletes %d/%d, events %d; want none", blocks.deletes, rules.deletes, len(audit.events))
	}
}
