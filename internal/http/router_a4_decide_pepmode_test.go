package http

import (
	"context"
	nethttp "net/http"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
)

// #323: an application whose PEP enforces while POLICY_MODE is off reports
// pep_mode, and its decisions are recorded under that mode. The answer keeps
// the server's mode.
func TestDecide_PEPMode_RecordsUnderTheStricterMode(t *testing.T) {
	f := newDecideFixture(t, policy.ModeOff)
	svc := f.serviceToken(t, f.billing)

	// A deny with pep_mode enforce: answered as off, recorded as enforced.
	r := f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"nothing.covers.this","pep_mode":"enforce"}`,
		"X-Correlation-ID", "corr-pep-enforce")
	if r.code != 200 || r.resp.Allow || r.resp.Mode != "off" || !r.resp.PEPAccepted {
		t.Fatalf("pep_mode enforce under off → %d %s", r.code, r.body)
	}
	d, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{CorrelationID: "corr-pep-enforce"})
	if len(d) != 1 || d[0].Mode != "enforce" || !d[0].Enforced || d[0].Allow || d[0].ClientID != "billing" {
		t.Fatalf("decision log = %+v, want one enforced deny", d)
	}

	// An unmet obligation with pep_mode shadow is recorded under shadow.
	body := `{"subject":{"token":"` + f.userToken(t, f.alice, "pwd") + `"},"action":"invoice.approve","resource":{"type":"invoice","id":"inv-9","attributes":{"amount":250}},"pep_mode":"shadow"}`
	r = f.decide(t, "3", svc, body, "X-Correlation-ID", "corr-pep-shadow")
	if r.code != 200 || !r.resp.Allow || r.resp.Mode != "off" {
		t.Fatalf("pep_mode shadow → %d %s", r.code, r.body)
	}
	d, _ = f.store.Decisions(context.Background(), policy.DecisionFilter{CorrelationID: "corr-pep-shadow"})
	if len(d) != 1 || d[0].Mode != "shadow" || d[0].Enforced || d[0].Reason != policy.ReasonObligationUnmet+":"+policy.ObligationMFA {
		t.Fatalf("decision log = %+v, want one shadow obligation_unmet row", d)
	}

	// pep_mode off (or absent) under off: nothing recorded, as before.
	f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"nothing.covers.this","pep_mode":"off"}`)
	f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"nothing.covers.this"}`)
	if all, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{}); len(all) != 2 {
		t.Fatalf("decision log has %d rows, want the 2 above only", len(all))
	}
}

// pep_mode can only make the record stricter, never lower the server's mode.
func TestDecide_PEPMode_CannotLowerTheServerMode(t *testing.T) {
	f := newDecideFixture(t, policy.ModeEnforce)
	r := f.decide(t, "3", f.serviceToken(t, f.billing), `{"subject":{"user_id":10},"action":"nothing.covers.this","pep_mode":"off"}`,
		"X-Correlation-ID", "corr-pep-lower")
	if r.code != 200 || r.resp.Mode != "enforce" {
		t.Fatalf("→ %d %s", r.code, r.body)
	}
	d, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{CorrelationID: "corr-pep-lower"})
	if len(d) != 1 || d[0].Mode != "enforce" || !d[0].Enforced {
		t.Fatalf("decision log = %+v, want the enforce row", d)
	}
}

func TestDecide_PEPMode_Validation(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	svc := f.serviceToken(t, f.billing)
	for _, v := range []string{"strict", "Enforce", " enforce", "on"} {
		r := f.decide(t, "3", svc, `{"action":"app.self-check","pep_mode":"`+v+`"}`)
		if r.code != nethttp.StatusBadRequest {
			t.Errorf("pep_mode %q → %d %s, want 400", v, r.code, r.body)
		}
	}
	// Every answer advertises that pep_mode is accepted.
	if r := f.decide(t, "3", svc, `{"action":"app.self-check"}`); r.code != 200 || !r.resp.PEPAccepted {
		t.Errorf("answer without pep_mode_accepted: %d %s", r.code, r.body)
	}
}

// An outage under off is recorded when the PEP enforces.
func TestDecide_PEPMode_RecordsAnOutage(t *testing.T) {
	f := newDecideFixture(t, policy.ModeOff)
	users := &decideUsers{users: map[uint]*model.User{10: f.alice}}
	roles := &decideRoles{roles: map[[2]uint]model.AppRole{{10, 3}: model.AppRoleAdmin}}
	store := policy.NewMemoryStore()
	empty := policy.NewService(store, policy.ModeOff, time.Nanosecond)
	f.h = newAdminRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		f.ts, users, nil, roles, &decideApps{apps: map[uint]*model.App{3: f.billing}},
		RouterConfig{PolicyDecideHandler: handler.NewPolicyDecideHandler(empty, f.ts, users, nil, roles)})

	svc := f.serviceToken(t, f.billing)
	if r := f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"a"}`); r.code != nethttp.StatusServiceUnavailable {
		t.Fatalf("no policy → %d %s", r.code, r.body)
	}
	if d, _ := store.Decisions(context.Background(), policy.DecisionFilter{}); len(d) != 0 {
		t.Fatalf("off without pep_mode recorded %d rows", len(d))
	}
	if r := f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"a","pep_mode":"enforce"}`); r.code != nethttp.StatusServiceUnavailable {
		t.Fatalf("no policy → %d %s", r.code, r.body)
	}
	d, _ := store.Decisions(context.Background(), policy.DecisionFilter{})
	if len(d) != 1 || d[0].Mode != "enforce" || d[0].StatusCode != nethttp.StatusServiceUnavailable {
		t.Fatalf("decision log = %+v, want one enforce 503 row", d)
	}
}
