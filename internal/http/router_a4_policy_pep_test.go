// Package http — A4 policy enforcement point on the admin API.
//
// These tests drive the REAL admin router (the P3-1 harness: real signed
// tokens, nil handlers, every registered /api/admin route) with the PEP
// installed, and check the properties the rollout depends on:
//
//   - shadow mode never changes a response;
//   - the seeded baseline agrees with the code gates on every route, for
//     every kind of principal — zero divergences;
//   - the baseline's step-up list is exactly the set of routes the router
//     wraps in RequireFreshAuth;
//   - enforce mode can refuse what the code allows, but never allow what the
//     code refuses;
//   - the policy editor stays reachable under any policy.
package http

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

const a4MaxAge = 5 * time.Minute

type a4Setup struct {
	store *policy.MemoryStore
	pdp   *policy.Service
	ph    *handler.PolicyHandler
}

// a4PDP returns a PDP in mode over a fresh store, seeded with rules (the
// baseline when rules is nil). A zero refresh interval would re-read the store
// on every call; 1ns keeps it re-reading so in-test saves apply immediately.
func a4PDP(t *testing.T, mode policy.Mode, rules []policy.Rule) *a4Setup {
	t.Helper()
	store := policy.NewMemoryStore()
	pdp := policy.NewService(store, mode, time.Nanosecond)
	if rules == nil {
		if _, err := pdp.EnsureBaseline(context.Background()); err != nil {
			t.Fatal(err)
		}
	} else if _, err := pdp.Save(context.Background(), 0, rules, "test", 1); err != nil {
		t.Fatal(err)
	}
	return &a4Setup{store: store, pdp: pdp, ph: handler.NewPolicyHandler(pdp, nil)}
}

// a4Router builds the real admin router. pdp nil means no PEP at all — the
// pre-A4 router, the reference every PEP mode is compared against.
func a4Router(t *testing.T, ts *auth.TokenService, user *model.User, s *a4Setup) nethttp.Handler {
	t.Helper()
	adminAuth := handler.NewAdminAuthHandler(nil, &p31UserService{user: user})
	cfg := RouterConfig{
		AdminElevationMaxAge: a4MaxAge,
		// Registered so the webhook routes — several of them step-up — are
		// part of the walk. Nil services: a request that reaches one panics,
		// which Recoverer turns into a 500, which is "the gates let it in".
		WebhookHandler: handler.NewWebhookHandler(nil, nil),
	}
	if s != nil {
		cfg.PolicyPEP = middleware.NewPolicyPEP(s.pdp, a4MaxAge)
		cfg.PolicyHandler = s.ph
	}
	return newAdminRouter(nil, adminAuth, nil, nil, nil, nil, nil, nil, nil, nil,
		ts, &p31UserRepo{user: user}, nil, nil, nil, cfg)
}

func a4Mint(t *testing.T, ts *auth.TokenService, user *model.User, authTime time.Time, amr ...string) string {
	t.Helper()
	app := &model.App{ID: 1, ClientID: "test-client"}
	set, err := ts.GenerateTokenSetWithAuth(user, app, string(user.Role), "openid admin", nil, "", authTime.Unix(), amr, "")
	if err != nil {
		t.Fatalf("GenerateTokenSetWithAuth: %v", err)
	}
	return set.AccessToken
}

type a4Response struct {
	code int
	body string
}

func a4Do(h nethttp.Handler, method, path, token string) a4Response {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return a4Response{code: rr.Code, body: strings.TrimSpace(rr.Body.String())}
}

// a4Principals are the cases the parity checks cover: each role, fresh and
// stale, plus an admin with a forced password change pending.
func a4Principals() []struct {
	name  string
	user  *model.User
	fresh bool
} {
	u := func(id uint, role model.UserRole, mustChange bool) *model.User {
		return &model.User{ID: id, Email: "u@example.com", Role: role, IsVerified: true, MustChangePassword: mustChange}
	}
	return []struct {
		name  string
		user  *model.User
		fresh bool
	}{
		{"user/fresh", u(42, model.UserRoleUser, false), true},
		{"admin/fresh", u(7, model.UserRoleAdmin, false), true},
		{"admin/stale", u(7, model.UserRoleAdmin, false), false},
		{"superadmin/fresh", u(1, model.UserRoleSuperadmin, false), true},
		{"superadmin/stale", u(1, model.UserRoleSuperadmin, false), false},
		{"admin/must-change-password", u(8, model.UserRoleAdmin, true), true},
	}
}

// a4Routes is the P3-1 route walk minus the SSE stream, which holds a request
// open for two seconds even with a nil handler — identical under every mode,
// and not worth a minute of test time across the principal matrix.
func a4Routes(t *testing.T, h nethttp.Handler) [][2]string {
	t.Helper()
	var out [][2]string
	for _, rt := range p31AdminRoutes(t, h) {
		if rt[1] != "/api/admin/events/stream" {
			out = append(out, rt)
		}
	}
	return out
}

func a4AuthTime(fresh bool) time.Time {
	if fresh {
		return time.Now()
	}
	return time.Now().Add(-2 * a4MaxAge)
}

// The two properties shadow mode exists for, checked on every admin route for
// every principal: it never changes a response, and the baseline agrees with
// the code gates everywhere.
func TestA4_Shadow_NeverChangesAResponse_AndBaselineHasNoDivergence(t *testing.T) {
	ts := p31TokenService(t)
	for _, p := range a4Principals() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			s := a4PDP(t, policy.ModeShadow, nil)
			ref := a4Router(t, ts, p.user, nil)
			shadow := a4Router(t, ts, p.user, s)
			tok := a4Mint(t, ts, p.user, a4AuthTime(p.fresh))

			for _, rt := range a4Routes(t, ref) {
				want := a4Do(ref, rt[0], rt[1], tok)
				got := a4Do(shadow, rt[0], rt[1], tok)
				if got != want {
					t.Errorf("%s %s: shadow answered %d %s, off answered %d %s",
						rt[0], rt[1], got.code, got.body, want.code, want.body)
				}
			}

			decisions, _ := s.store.Decisions(context.Background(), policy.DecisionFilter{})
			for _, d := range decisions {
				if d.Divergence != "" {
					t.Errorf("divergence %s on %s (rule %q, reason %s, status %d)",
						d.Divergence, d.Action, d.Rule, d.Reason, d.StatusCode)
				}
				if d.Enforced {
					t.Errorf("shadow decision on %s marked enforced", d.Action)
				}
			}
		})
	}
}

// policy.StepUpActions is a hand-maintained copy of which routes the router
// wraps in RequireFreshAuth. Derive the real set from behaviour and compare,
// so the two cannot drift silently.
func TestA4_BaselineStepUpList_MatchesTheRouter(t *testing.T) {
	ts := p31TokenService(t)
	sa := &model.User{ID: 1, Email: "root@example.com", Role: model.UserRoleSuperadmin, IsVerified: true}
	h := a4Router(t, ts, sa, nil)
	stale := a4Mint(t, ts, sa, a4AuthTime(false))

	var actual []string
	for _, action := range a4Actions(t) {
		method, pattern, _ := strings.Cut(action, " ")
		path := strings.NewReplacer("{id}", "1", "{ip}", "203.0.113.9", "{version}", "1").Replace(pattern)
		if r := a4Do(h, method, path, stale); r.code == nethttp.StatusForbidden && strings.Contains(r.body, "elevation_required") {
			actual = append(actual, action)
		}
	}
	want := append([]string(nil), policy.StepUpActions...)
	sort.Strings(actual)
	sort.Strings(want)
	if !slices.Equal(actual, want) {
		t.Fatalf("step-up routes drifted from policy.StepUpActions\n router: %v\n policy: %v", actual, want)
	}
}

// a4Actions lists the router's gated admin actions via the policy catalogue,
// i.e. the same walk the PEP's editor sees.
func a4Actions(t *testing.T) []string {
	t.Helper()
	var cat struct {
		AdminActions []string `json:"admin_actions"`
	}
	body := a4CatalogueBody(t, a4PDP(t, policy.ModeOff, nil))
	if err := json.Unmarshal([]byte(body), &cat); err != nil {
		t.Fatalf("catalogue: %v (%s)", err, body)
	}
	if len(cat.AdminActions) < 30 {
		t.Fatalf("only %d admin actions in the catalogue — walk looks broken", len(cat.AdminActions))
	}
	return cat.AdminActions
}

func a4CatalogueBody(t *testing.T, s *a4Setup) string {
	t.Helper()
	ts := p31TokenService(t)
	sa := &model.User{ID: 1, Email: "root@example.com", Role: model.UserRoleSuperadmin, IsVerified: true}
	h := a4Router(t, ts, sa, s)
	r := a4Do(h, nethttp.MethodGet, "/api/admin/policy/catalogue", a4Mint(t, ts, sa, time.Now()))
	if r.code != nethttp.StatusOK {
		t.Fatalf("GET /api/admin/policy/catalogue → %d %s", r.code, r.body)
	}
	return r.body
}

func TestA4_Catalogue_ListsRealActions_AndExemptsThePolicyEditor(t *testing.T) {
	s := a4PDP(t, policy.ModeShadow, nil)
	var cat struct {
		AdminActions  []string `json:"admin_actions"`
		ExemptActions []string `json:"exempt_actions"`
		Mode          string   `json:"mode"`
	}
	if err := json.Unmarshal([]byte(a4CatalogueBody(t, s)), &cat); err != nil {
		t.Fatal(err)
	}
	if cat.Mode != "shadow" {
		t.Errorf("mode = %q, want shadow", cat.Mode)
	}
	for _, a := range policy.StepUpActions {
		if !slices.Contains(cat.AdminActions, a) {
			t.Errorf("baseline step-up action %q is not a real admin action", a)
		}
	}
	for _, a := range []string{"PUT /api/admin/policy", "POST /api/admin/elevate", "POST /api/admin/change-password"} {
		if !slices.Contains(cat.ExemptActions, a) {
			t.Errorf("%q should be exempt from the PEP", a)
		}
		if slices.Contains(cat.AdminActions, a) {
			t.Errorf("%q listed as a gated action", a)
		}
	}
}

// With the baseline, enforce mode must refuse exactly what the code gates
// refuse — same status on every route, for every principal.
func TestA4_Enforce_WithBaseline_MatchesTheCodeGates(t *testing.T) {
	ts := p31TokenService(t)
	for _, p := range a4Principals() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			s := a4PDP(t, policy.ModeEnforce, nil)
			ref := a4Router(t, ts, p.user, nil)
			enf := a4Router(t, ts, p.user, s)
			tok := a4Mint(t, ts, p.user, a4AuthTime(p.fresh))
			for _, rt := range a4Routes(t, ref) {
				want := a4Do(ref, rt[0], rt[1], tok).code
				if got := a4Do(enf, rt[0], rt[1], tok).code; got != want {
					t.Errorf("%s %s: enforce → %d, code gates → %d", rt[0], rt[1], got, want)
				}
			}
		})
	}
}

func TestA4_Enforce_CanRefuseWhatTheCodeAllows(t *testing.T) {
	ts := p31TokenService(t)
	sa := &model.User{ID: 1, Email: "root@example.com", Role: model.UserRoleSuperadmin, IsVerified: true}
	rules := append(policy.Baseline(), policy.Rule{
		ID: "no-client-deletion", Effect: policy.EffectDeny,
		Actions: []string{"DELETE /api/admin/apps/{id}"},
	})

	s := a4PDP(t, policy.ModeEnforce, rules)
	h := a4Router(t, ts, sa, s)
	r := a4Do(h, nethttp.MethodDelete, "/api/admin/apps/5", a4Mint(t, ts, sa, time.Now()))
	if r.code != nethttp.StatusForbidden || !strings.Contains(r.body, "policy_denied") {
		t.Fatalf("enforce: DELETE app → %d %s, want 403 policy_denied", r.code, r.body)
	}
	decisions, _ := s.store.Decisions(context.Background(), policy.DecisionFilter{})
	if len(decisions) != 1 || !decisions[0].Enforced || decisions[0].Rule != "no-client-deletion" ||
		decisions[0].ResourceType != "apps" || decisions[0].ResourceID != "5" ||
		decisions[0].Action != "DELETE /api/admin/apps/{id}" || decisions[0].StatusCode != 403 {
		t.Fatalf("decision log = %+v", decisions)
	}

	// The same rule in shadow: the request goes through (to the nil handler)
	// and the disagreement is recorded instead.
	s = a4PDP(t, policy.ModeShadow, rules)
	h = a4Router(t, ts, sa, s)
	if r := a4Do(h, nethttp.MethodDelete, "/api/admin/apps/5", a4Mint(t, ts, sa, time.Now())); r.code == nethttp.StatusForbidden {
		t.Fatalf("shadow refused the request: %d %s", r.code, r.body)
	}
	decisions, _ = s.store.Decisions(context.Background(), policy.DecisionFilter{})
	if len(decisions) != 1 || decisions[0].Divergence != policy.DivergencePDPStricter || decisions[0].Enforced {
		t.Fatalf("shadow decision log = %+v, want one pdp_deny_code_allow", decisions)
	}
}

// The safety property of enforce mode: a policy that allows everything to
// everyone still cannot let a plain user past the code gates.
func TestA4_Enforce_NeverGrantsWhatTheCodeRefuses(t *testing.T) {
	ts := p31TokenService(t)
	user := &model.User{ID: 42, Email: "user@example.com", Role: model.UserRoleUser, IsVerified: true}
	s := a4PDP(t, policy.ModeEnforce, []policy.Rule{{ID: "everyone", Effect: policy.EffectAllow, Actions: []string{"*"}}})
	h := a4Router(t, ts, user, s)
	tok := a4Mint(t, ts, user, time.Now())

	for _, rt := range p31AdminRoutes(t, h) {
		if code := a4Do(h, rt[0], rt[1], tok).code; code != nethttp.StatusForbidden {
			t.Errorf("allow-all policy let role=user reach %s %s → %d", rt[0], rt[1], code)
		}
	}
	// Every one of those is a disagreement the log must surface: this is the
	// list that has to be empty before a code gate can be retired.
	decisions, _ := s.store.Decisions(context.Background(), policy.DecisionFilter{DivergenceOnly: true})
	if len(decisions) == 0 {
		t.Fatal("no pdp_allow_code_deny divergences recorded")
	}
}

func TestA4_Enforce_Obligations(t *testing.T) {
	ts := p31TokenService(t)
	admin := &model.User{ID: 7, Email: "admin@example.com", Role: model.UserRoleAdmin, IsVerified: true}
	rules := []policy.Rule{{
		ID: "mfa-for-stats", Effect: policy.EffectAllow,
		Actions: []string{"GET /api/admin/stats"}, Obligations: []string{policy.ObligationMFA},
	}}
	s := a4PDP(t, policy.ModeEnforce, rules)
	h := a4Router(t, ts, admin, s)

	r := a4Do(h, nethttp.MethodGet, "/api/admin/stats", a4Mint(t, ts, admin, time.Now(), "pwd"))
	if r.code != nethttp.StatusForbidden || !strings.Contains(r.body, "mfa_required") {
		t.Fatalf("password-only token → %d %s, want 403 mfa_required", r.code, r.body)
	}
	r = a4Do(h, nethttp.MethodGet, "/api/admin/stats", a4Mint(t, ts, admin, time.Now(), "pwd", "otp", "mfa"))
	if r.code == nethttp.StatusForbidden {
		t.Fatalf("MFA token refused: %d %s", r.code, r.body)
	}
}

// One bad rule in enforce mode must not be able to lock out the only place it
// can be fixed.
func TestA4_Enforce_DenyAll_LeavesThePolicyEditorReachable(t *testing.T) {
	ts := p31TokenService(t)
	sa := &model.User{ID: 1, Email: "root@example.com", Role: model.UserRoleSuperadmin, IsVerified: true}
	s := a4PDP(t, policy.ModeEnforce, []policy.Rule{{ID: "lockout", Effect: policy.EffectDeny, Actions: []string{"*"}}})
	h := a4Router(t, ts, sa, s)
	tok := a4Mint(t, ts, sa, time.Now())

	if r := a4Do(h, nethttp.MethodGet, "/api/admin/stats", tok); r.code != nethttp.StatusForbidden {
		t.Fatalf("deny-all did not deny /stats: %d", r.code)
	}
	if r := a4Do(h, nethttp.MethodGet, "/api/admin/policy", tok); r.code != nethttp.StatusOK {
		t.Fatalf("policy editor unreachable under deny-all: %d %s", r.code, r.body)
	}

	// Repair it through the API, from the locked-out state.
	req := httptest.NewRequest(nethttp.MethodPost, "/api/admin/policy/versions/1/restore", strings.NewReader(`{"base_version":1}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != nethttp.StatusOK {
		t.Fatalf("restore → %d %s", rr.Code, rr.Body.String())
	}
	// The restored version is the same deny-all (version 1 was the lockout),
	// so save a working one instead.
	saveBody, _ := json.Marshal(map[string]any{"base_version": 2, "rules": policy.Baseline(), "note": "recover"})
	req = httptest.NewRequest(nethttp.MethodPut, "/api/admin/policy", strings.NewReader(string(saveBody)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != nethttp.StatusOK {
		t.Fatalf("save baseline → %d %s", rr.Code, rr.Body.String())
	}
	if r := a4Do(h, nethttp.MethodGet, "/api/admin/profile", tok); r.code != nethttp.StatusOK {
		t.Fatalf("after recovery GET /profile → %d %s", r.code, r.body)
	}
}

func TestA4_Enforce_NoPolicyStored_FailsClosedButStaysRepairable(t *testing.T) {
	ts := p31TokenService(t)
	sa := &model.User{ID: 1, Email: "root@example.com", Role: model.UserRoleSuperadmin, IsVerified: true}
	store := policy.NewMemoryStore()
	pdp := policy.NewService(store, policy.ModeEnforce, time.Nanosecond)
	s := &a4Setup{store: store, pdp: pdp, ph: handler.NewPolicyHandler(pdp, nil)}
	h := a4Router(t, ts, sa, s)
	tok := a4Mint(t, ts, sa, time.Now())

	r := a4Do(h, nethttp.MethodGet, "/api/admin/profile", tok)
	if r.code != nethttp.StatusServiceUnavailable || !strings.Contains(r.body, "policy_unavailable") {
		t.Fatalf("no policy in enforce → %d %s, want 503 policy_unavailable", r.code, r.body)
	}
	body, _ := json.Marshal(map[string]any{"base_version": 0, "rules": policy.Baseline()})
	req := httptest.NewRequest(nethttp.MethodPut, "/api/admin/policy", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != nethttp.StatusOK {
		t.Fatalf("PUT /policy with no policy stored → %d %s", rr.Code, rr.Body.String())
	}
	if r := a4Do(h, nethttp.MethodGet, "/api/admin/profile", tok); r.code != nethttp.StatusOK {
		t.Fatalf("after saving a policy GET /profile → %d %s", r.code, r.body)
	}
}

// The policy API is superadmin-only, and its writes need step-up — enforced
// by the code gates, since the PEP deliberately does not cover it.
func TestA4_PolicyAPI_SuperadminOnly_WritesNeedStepUp(t *testing.T) {
	ts := p31TokenService(t)
	s := a4PDP(t, policy.ModeShadow, nil)

	admin := &model.User{ID: 7, Email: "admin@example.com", Role: model.UserRoleAdmin, IsVerified: true}
	h := a4Router(t, ts, admin, s)
	if r := a4Do(h, nethttp.MethodGet, "/api/admin/policy", a4Mint(t, ts, admin, time.Now())); r.code != nethttp.StatusForbidden {
		t.Fatalf("role=admin GET /policy → %d, want 403", r.code)
	}

	sa := &model.User{ID: 1, Email: "root@example.com", Role: model.UserRoleSuperadmin, IsVerified: true}
	h = a4Router(t, ts, sa, s)
	stale := a4Mint(t, ts, sa, a4AuthTime(false))
	if r := a4Do(h, nethttp.MethodGet, "/api/admin/policy", stale); r.code != nethttp.StatusOK {
		t.Fatalf("superadmin GET /policy → %d %s", r.code, r.body)
	}
	if r := a4Do(h, nethttp.MethodPut, "/api/admin/policy", stale); r.code != nethttp.StatusForbidden || !strings.Contains(r.body, "elevation_required") {
		t.Fatalf("stale PUT /policy → %d %s, want 403 elevation_required", r.code, r.body)
	}
	if r := a4Do(h, nethttp.MethodPost, "/api/admin/policy/versions/1/restore", stale); r.code != nethttp.StatusForbidden {
		t.Fatalf("stale restore → %d, want 403", r.code)
	}
}

func a4Call(t *testing.T, h nethttp.Handler, method, path, token, body string) a4Response {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return a4Response{code: rr.Code, body: strings.TrimSpace(rr.Body.String())}
}

func TestA4_PolicyAPI_ValidateSimulateVersionsDecisions(t *testing.T) {
	ts := p31TokenService(t)
	sa := &model.User{ID: 1, Email: "root@example.com", Role: model.UserRoleSuperadmin, IsVerified: true}
	s := a4PDP(t, policy.ModeShadow, nil)
	h := a4Router(t, ts, sa, s)
	tok := a4Mint(t, ts, sa, time.Now())

	// Validate: a clean draft, then one with two independent problems.
	if r := a4Call(t, h, "POST", "/api/admin/policy/validate", tok,
		`{"rules":[{"id":"ok","effect":"allow","actions":["*"]}]}`); r.code != 200 || !strings.Contains(r.body, `"valid":true`) {
		t.Fatalf("validate ok → %d %s", r.code, r.body)
	}
	r := a4Call(t, h, "POST", "/api/admin/policy/validate", tok,
		`{"rules":[{"id":"a","effect":"maybe","actions":["*"]},{"id":"b","effect":"deny","actions":["*"],"when":{"attr":"principal.scopes","op":"eq","value":"admin"}}]}`)
	if r.code != nethttp.StatusUnprocessableEntity || !strings.Contains(r.body, `"invalid_policy"`) ||
		!strings.Contains(r.body, `"effect"`) || !strings.Contains(r.body, "is a list") {
		t.Fatalf("validate bad → %d %s, want 422 listing both problems", r.code, r.body)
	}
	if n, _ := s.store.LatestVersion(context.Background()); n != 1 {
		t.Fatalf("validate stored a version: latest = %d", n)
	}

	// Simulate against the current version, and against a draft with a pinned time.
	r = a4Call(t, h, "POST", "/api/admin/policy/simulate", tok,
		`{"input":{"principal":{"kind":"user","id":7,"role":"admin"},"action":"GET /api/admin/superadmins"}}`)
	if r.code != 200 || !strings.Contains(r.body, `"rule":"superadmin-management"`) || !strings.Contains(r.body, `"allow":false`) {
		t.Fatalf("simulate current → %d %s", r.code, r.body)
	}
	r = a4Call(t, h, "POST", "/api/admin/policy/simulate", tok,
		`{"at":"2026-01-01T03:00:00Z","input":{"action":"x"},"rules":[{"id":"night","effect":"deny","actions":["*"],"when":{"attr":"context.hour_utc","op":"lt","value":6}}]}`)
	if r.code != 200 || !strings.Contains(r.body, `"rule":"night"`) {
		t.Fatalf("simulate draft at 03:00 → %d %s", r.code, r.body)
	}

	// Versions.
	if r := a4Call(t, h, "GET", "/api/admin/policy/versions", tok, ""); r.code != 200 || !strings.Contains(r.body, `"rule_count":4`) {
		t.Fatalf("versions → %d %s", r.code, r.body)
	}
	if r := a4Call(t, h, "GET", "/api/admin/policy/versions/1", tok, ""); r.code != 200 || !strings.Contains(r.body, `"global-admins"`) {
		t.Fatalf("version 1 → %d %s", r.code, r.body)
	}
	if r := a4Call(t, h, "GET", "/api/admin/policy/versions/99", tok, ""); r.code != nethttp.StatusNotFound {
		t.Fatalf("version 99 → %d, want 404", r.code)
	}
	if r := a4Call(t, h, "GET", "/api/admin/policy/versions/zero", tok, ""); r.code != nethttp.StatusBadRequest {
		t.Fatalf("version zero → %d, want 400", r.code)
	}

	// Decisions: filters parse, bad ones are refused.
	s.pdp.Record(context.Background(), &policy.DecisionRecord{CorrelationID: "c-9", Source: policy.SourceAdminPEP, Mode: "shadow", Action: "GET /x", Reason: "r"})
	if r := a4Call(t, h, "GET", "/api/admin/policy/decisions?correlation_id=c-9&allow=false&divergence=true&since=2026-01-01T00:00:00Z&before_id=10&limit=5", tok, ""); r.code != 200 {
		t.Fatalf("decisions with filters → %d %s", r.code, r.body)
	}
	for _, q := range []string{"allow=perhaps", "since=yesterday", "before_id=x"} {
		if r := a4Call(t, h, "GET", "/api/admin/policy/decisions?"+q, tok, ""); r.code != nethttp.StatusBadRequest {
			t.Errorf("decisions?%s → %d, want 400", q, r.code)
		}
	}
}
