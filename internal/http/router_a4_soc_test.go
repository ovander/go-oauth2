// Package http — A4 part 3: the SOC's read-only view of the policy decision
// log, on the real admin router.
package http

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// socRouter builds the admin router with scope gates enforced, as a deployment
// with ADMIN_SCOPE_MODE=enforce runs it — the monitoring console then holds
// only monitoring:read / monitoring:write.
func socRouter(t *testing.T, ts *auth.TokenService, user *model.User, s *a4Setup) nethttp.Handler {
	t.Helper()
	adminAuth := handler.NewAdminAuthHandler(nil, &p31UserService{user: user})
	return newAdminRouter(nil, adminAuth, nil, nil, nil, nil, nil, nil, nil, nil,
		ts, &p31UserRepo{user: user}, nil, nil, nil, RouterConfig{
			AdminElevationMaxAge: a4MaxAge,
			ScopeEnforce:         true,
			PolicyPEP:            middleware.NewPolicyPEP(s.pdp, a4MaxAge),
			PolicyHandler:        s.ph,
		})
}

func socMint(t *testing.T, ts *auth.TokenService, user *model.User, scope string) string {
	t.Helper()
	set, err := ts.GenerateTokenSetWithAuth(user, &model.App{ID: 2, ClientID: "monitoring-bff"},
		string(user.Role), scope, nil, "", time.Now().Unix(), []string{"pwd"}, "")
	if err != nil {
		t.Fatal(err)
	}
	return set.AccessToken
}

func seedDecisions(t *testing.T, pdp *policy.Service) {
	t.Helper()
	uid := uint(7)
	for _, r := range []policy.DecisionRecord{
		{Source: policy.SourceAdminPEP, Mode: "shadow", Action: "GET /api/admin/stats", Reason: "denied_by_rule", Divergence: policy.DivergencePDPStricter, PrincipalID: &uid, CorrelationID: "c-1"},
		{Source: "decide_api", Mode: "enforce", Enforced: true, Action: "invoice.approve", Reason: "denied_by_rule", ClientID: "billing", CorrelationID: "c-2"},
		{Source: "decide_api", Mode: "enforce", Enforced: true, Action: "invoice.approve", Reason: "denied_by_rule", ClientID: "crm", CorrelationID: "c-3"},
		{Source: policy.SourceAdminPEP, Mode: "shadow", Allow: true, Action: "GET /api/admin/users", Reason: "allowed_by_rule", Divergence: policy.DivergencePDPLooser, CorrelationID: "c-4"},
	} {
		rec := r
		pdp.Record(context.Background(), &rec)
	}
}

func socGet(t *testing.T, h nethttp.Handler, path, tok string) (int, map[string]json.RawMessage) {
	t.Helper()
	req := httptest.NewRequest(nethttp.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var body map[string]json.RawMessage
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

// The monitoring console — a global admin holding only monitoring:read — can
// read the decision log, and cannot read or change the rules.
func TestSOC_MonitoringScope_ReadsDecisions_NotRules(t *testing.T) {
	ts := p31TokenService(t)
	s := a4PDP(t, policy.ModeShadow, nil)
	seedDecisions(t, s.pdp)
	admin := &model.User{ID: 7, Email: "soc@example.com", Role: model.UserRoleAdmin, IsVerified: true}
	h := socRouter(t, ts, admin, s)
	tok := socMint(t, ts, admin, "openid monitoring:read")

	code, body := socGet(t, h, "/api/admin/security/policy-decisions", tok)
	if code != nethttp.StatusOK {
		t.Fatalf("SOC decisions → %d", code)
	}
	var rows []policy.DecisionRecord
	_ = json.Unmarshal(body["decisions"], &rows)
	if len(rows) != 4 || string(body["mode"]) != `"shadow"` {
		t.Fatalf("rows=%d mode=%s", len(rows), body["mode"])
	}

	for _, path := range []string{"/api/admin/policy", "/api/admin/policy/decisions", "/api/admin/policy/catalogue"} {
		if code, _ := socGet(t, h, path, tok); code != nethttp.StatusForbidden {
			t.Errorf("monitoring-scoped admin GET %s → %d, want 403", path, code)
		}
	}
}

func TestSOC_PlainUser_Refused(t *testing.T) {
	ts := p31TokenService(t)
	s := a4PDP(t, policy.ModeShadow, nil)
	user := &model.User{ID: 42, Email: "u@example.com", Role: model.UserRoleUser, IsVerified: true}
	h := socRouter(t, ts, user, s)
	tok := socMint(t, ts, user, "openid monitoring:read")
	for _, path := range []string{"/api/admin/security/policy-decisions", "/api/admin/security/policy-decisions/summary"} {
		if code, _ := socGet(t, h, path, tok); code != nethttp.StatusForbidden {
			t.Errorf("role=user GET %s → %d, want 403", path, code)
		}
	}
}

func TestSOC_Filters(t *testing.T) {
	ts := p31TokenService(t)
	s := a4PDP(t, policy.ModeShadow, nil)
	seedDecisions(t, s.pdp)
	admin := &model.User{ID: 7, Email: "soc@example.com", Role: model.UserRoleAdmin, IsVerified: true}
	h := socRouter(t, ts, admin, s)
	tok := socMint(t, ts, admin, "openid monitoring:read")

	cases := map[string][]string{
		"?source=decide_api":            {"c-3", "c-2"},
		"?client_id=billing":            {"c-2"},
		"?divergence=true":              {"c-4", "c-1"},
		"?allow=false&source=admin_pep": {"c-1"},
		"?correlation_id=c-3":           {"c-3"},
		"?limit=1":                      {"c-4"},
		"?since=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339): {},
	}
	for q, want := range cases {
		code, body := socGet(t, h, "/api/admin/security/policy-decisions"+q, tok)
		var rows []policy.DecisionRecord
		_ = json.Unmarshal(body["decisions"], &rows)
		got := make([]string, len(rows))
		for i, r := range rows {
			got[i] = r.CorrelationID
		}
		if code != 200 || len(got) != len(want) {
			t.Errorf("%s → %d %v, want %v", q, code, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s → %v, want %v (newest first)", q, got, want)
				break
			}
		}
	}
	for _, q := range []string{"?allow=maybe", "?since=yesterday", "?before_id=x"} {
		if code, _ := socGet(t, h, "/api/admin/security/policy-decisions"+q, tok); code != nethttp.StatusBadRequest {
			t.Errorf("%s → %d, want 400", q, code)
		}
	}
}

func TestSOC_Summary(t *testing.T) {
	ts := p31TokenService(t)
	s := a4PDP(t, policy.ModeEnforce, nil)
	seedDecisions(t, s.pdp)
	admin := &model.User{ID: 7, Email: "soc@example.com", Role: model.UserRoleAdmin, IsVerified: true}
	h := socRouter(t, ts, admin, s)
	tok := socMint(t, ts, admin, "openid monitoring:read")

	code, body := socGet(t, h, "/api/admin/security/policy-decisions/summary", tok)
	if code != 200 {
		t.Fatalf("summary → %d", code)
	}
	var sum policy.DecisionSummary
	_ = json.Unmarshal(body["summary"], &sum)
	if sum.Denials != 3 || sum.EnforcedDenials != 2 ||
		sum.Divergences[policy.DivergencePDPStricter] != 1 || sum.Divergences[policy.DivergencePDPLooser] != 1 ||
		sum.DenialsBySource["decide_api"] != 2 || sum.DenialsBySource[policy.SourceAdminPEP] != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if string(body["mode"]) != `"enforce"` || string(body["policy_version"]) != "1" {
		t.Fatalf("mode=%s version=%s", body["mode"], body["policy_version"])
	}
	if code, _ := socGet(t, h, "/api/admin/security/policy-decisions/summary?since=nope", tok); code != nethttp.StatusBadRequest {
		t.Fatalf("bad since → %d", code)
	}
	// A window that starts in the future counts nothing.
	_, body = socGet(t, h, "/api/admin/security/policy-decisions/summary?since="+time.Now().Add(time.Hour).UTC().Format(time.RFC3339), tok)
	_ = json.Unmarshal(body["summary"], &sum)
	if sum.Denials != 0 {
		t.Fatalf("future window counted %d denials", sum.Denials)
	}
}
