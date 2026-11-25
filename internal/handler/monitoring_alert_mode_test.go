package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// listedRules lists one alert rule.
type listedRules struct{ repository.AlertRuleRepository }

func (listedRules) FindAll(context.Context) ([]model.AlertRule, error) {
	return []model.AlertRule{{ID: 1, Name: "r", EventType: "login_failed"}}, nil
}

// #258: the alert-rule list says whether the rules are evaluated, so the
// monitoring console can tell its operators.
func TestListAlertRules_ReportsTheEvaluationMode(t *testing.T) {
	for set, want := range map[string]string{"": "off", "off": "off", "observe": "observe", "enforce": "enforce"} {
		h := &MonitoringHandler{alertRuleRepo: listedRules{}}
		h.SetAlertRulesMode(set)
		w := call(h.ListAlertRules, http.MethodGet, "", "")
		var resp dto.AlertRulesListResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
			t.Fatalf("mode %q: %d %v", set, w.Code, err)
		}
		if resp.EvaluationMode != want || resp.Total != 1 {
			t.Errorf("mode %q: evaluation_mode = %q, total %d; want %q, 1", set, resp.EvaluationMode, resp.Total, want)
		}
	}
}
