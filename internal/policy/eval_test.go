package policy

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// mustRules decodes a rule set from JSON the way the admin API receives it,
// so values arrive as float64 / []any exactly as in production.
func mustRules(t *testing.T, raw string) []Rule {
	t.Helper()
	var rules []Rule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	if errs := Validate(rules); len(errs) > 0 {
		t.Fatalf("rules do not validate: %v", errs)
	}
	return rules
}

func adminInput(role, action string) Input {
	return Input{
		Principal: Principal{Kind: PrincipalUser, ID: 7, Role: role, Scopes: []string{}, AMR: []string{"pwd"}},
		Action:    action,
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything at all", true},
		{"GET /api/admin/apps", "GET /api/admin/apps", true},
		{"GET /api/admin/apps", "GET /api/admin/apps/{id}", false},
		{"* /api/admin/*", "DELETE /api/admin/apps/{id}", true},
		{"* /api/admin/*", "GET /api/adminx", false},
		{"* /api/admin/superadmins*", "PUT /api/admin/superadmins/{id}", true},
		{"invoice.*", "invoice.approve", true},
		{"invoice.*", "invoices.approve", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"**", "x", true},
		// A pathological pattern must stay fast (no exponential backtracking).
		{"*a*a*a*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestDecide_DefaultDeny(t *testing.T) {
	e := NewEngine(3, nil)
	d := e.Decide(adminInput("admin", "GET /api/admin/stats"))
	if d.Allow || d.Reason != ReasonNoApplicable || d.Version != 3 {
		t.Fatalf("empty rule set: got %+v, want deny/no_applicable_rule/v3", d)
	}
}

func TestDecide_DenyOverridesAllow(t *testing.T) {
	rules := mustRules(t, `[
		{"id":"allow-all","effect":"allow","actions":["*"]},
		{"id":"no-deletes","effect":"deny","actions":["DELETE *"]}
	]`)
	e := NewEngine(1, rules)

	if d := e.Decide(adminInput("admin", "GET /x")); !d.Allow || d.Rule != "allow-all" {
		t.Errorf("GET: got %+v, want allow by allow-all", d)
	}
	// The deny is listed after the allow and still wins: order never matters.
	if d := e.Decide(adminInput("admin", "DELETE /x")); d.Allow || d.Rule != "no-deletes" || d.Reason != ReasonDenied {
		t.Errorf("DELETE: got %+v, want deny by no-deletes", d)
	}
}

func TestDecide_ObligationsAreUnionOfApplicableAllows(t *testing.T) {
	rules := mustRules(t, `[
		{"id":"a","effect":"allow","actions":["*"],"obligations":["require_mfa"]},
		{"id":"b","effect":"allow","actions":["POST *"],"obligations":["require_fresh_auth","require_mfa"]},
		{"id":"c","effect":"allow","actions":["POST *"],"when":{"attr":"principal.role","op":"eq","value":"nobody"},"obligations":["require_fresh_auth"]}
	]`)
	e := NewEngine(1, rules)

	d := e.Decide(adminInput("admin", "POST /x"))
	want := []string{ObligationMFA, ObligationFreshAuth}
	if !d.Allow || !reflect.DeepEqual(sortedCopy(d.Obligations), sortedCopy(want)) {
		t.Fatalf("got %+v, want allow with %v", d, want)
	}
	d = e.Decide(adminInput("admin", "GET /x"))
	if !reflect.DeepEqual(d.Obligations, []string{ObligationMFA}) {
		t.Fatalf("GET: obligations %v, want only require_mfa (rule c does not apply)", d.Obligations)
	}
}

func sortedCopy(ss []string) []string {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return sortedKeys(m)
}

// The central safety property of three-valued evaluation: a missing attribute
// can make the policy stricter, never looser.
func TestDecide_MissingAttribute_DenyFailsClosed_AllowFailsClosed(t *testing.T) {
	rules := mustRules(t, `[
		{"id":"staff","effect":"allow","actions":["*"],
		 "when":{"attr":"principal.attributes.department","op":"eq","value":"finance"}},
		{"id":"non-finance-blocked","effect":"deny","actions":["pay"],
		 "when":{"attr":"principal.attributes.department","op":"ne","value":"finance"}}
	]`)
	e := NewEngine(1, rules)

	noDept := adminInput("user", "pay") // no attributes at all
	d := e.Decide(noDept)
	if d.Allow || d.Rule != "non-finance-blocked" || d.Reason != ReasonIndeterminate {
		t.Fatalf("missing department on a deny rule: got %+v, want indeterminate deny", d)
	}

	// The same missing attribute on an allow rule does not allow.
	d = e.Decide(adminInput("user", "read"))
	if d.Allow {
		t.Fatalf("missing department on an allow rule: got %+v, want deny", d)
	}

	fin := adminInput("user", "pay")
	fin.Principal.Attributes = map[string]any{"department": "finance"}
	if d := e.Decide(fin); !d.Allow || d.Rule != "staff" {
		t.Fatalf("finance user: got %+v, want allow", d)
	}
}

func TestDecide_ExistsIsNeverUnknown(t *testing.T) {
	rules := mustRules(t, `[
		{"id":"needs-tenant","effect":"deny","actions":["*"],
		 "when":{"not":{"attr":"principal.attributes.tenant","op":"exists"}}},
		{"id":"ok","effect":"allow","actions":["*"]}
	]`)
	e := NewEngine(1, rules)
	if d := e.Decide(adminInput("user", "x")); d.Allow || d.Reason != ReasonDenied {
		t.Fatalf("no tenant: got %+v, want a definite (not indeterminate) deny", d)
	}
	in := adminInput("user", "x")
	in.Principal.Attributes = map[string]any{"tenant": "acme"}
	if d := e.Decide(in); !d.Allow {
		t.Fatalf("with tenant: got %+v, want allow", d)
	}
}

func TestDecide_KleeneLogic(t *testing.T) {
	missing := Condition{Attr: "principal.attributes.nope", Op: opEq, Value: "x"}
	yes := Condition{Attr: "principal.role", Op: opEq, Value: "admin"}
	no := Condition{Attr: "principal.role", Op: opEq, Value: "user"}

	cases := []struct {
		name string
		c    Condition
		want tri
	}{
		{"all(T,U)=U", Condition{All: []Condition{yes, missing}}, triUnknown},
		{"all(F,U)=F", Condition{All: []Condition{no, missing}}, triFalse},
		{"any(T,U)=T", Condition{Any: []Condition{missing, yes}}, triTrue},
		{"any(F,U)=U", Condition{Any: []Condition{no, missing}}, triUnknown},
		{"not(U)=U", Condition{Not: &missing}, triUnknown},
		{"not(F)=T", Condition{Not: &no}, triTrue},
	}
	in := adminInput("admin", "x")
	for _, c := range cases {
		ev := evaluator{in: &in, now: time.Now()}
		if got := ev.eval(&c.c); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDecide_Operators(t *testing.T) {
	now := time.Date(2026, 9, 27, 14, 30, 0, 0, time.UTC)
	in := Input{
		Principal: Principal{
			Kind: PrincipalUser, ID: 42, Role: "admin", ClientID: "console",
			Scopes: []string{"openid", "admin"}, AMR: []string{"pwd", "mfa"},
			AuthTime:   now.Add(-90 * time.Second).Unix(),
			Attributes: map[string]any{"level": float64(3), "groups": []any{"ops", "sre"}, "owner": float64(42)},
		},
		App:      &App{ID: 5, ClientID: "billing"},
		Action:   "invoice.approve",
		Resource: Resource{Type: "invoice", ID: "inv-9", Attributes: map[string]any{"owner_id": float64(42), "amount": float64(1200)}},
		Context:  Env{IP: "10.1.2.3", Now: now},
	}

	cases := []struct {
		name string
		when string
		want bool
	}{
		{"eq number vs uint id", `{"attr":"principal.id","op":"eq","value":42}`, true},
		{"ne", `{"attr":"principal.role","op":"ne","value":"superadmin"}`, true},
		{"in", `{"attr":"principal.role","op":"in","value":["admin","superadmin"]}`, true},
		{"not_in", `{"attr":"principal.role","op":"not_in","value":["admin"]}`, false},
		{"contains scope", `{"attr":"principal.scopes","op":"contains","value":"admin"}`, true},
		{"contains amr", `{"attr":"principal.amr","op":"contains","value":"mfa"}`, true},
		{"contains attribute list", `{"attr":"principal.attributes.groups","op":"contains","value":"sre"}`, true},
		{"auth_time_age lt", `{"attr":"principal.auth_time_age","op":"lt","value":300}`, true},
		{"auth_time_age gt", `{"attr":"principal.auth_time_age","op":"gt","value":60}`, true},
		{"lte boundary", `{"attr":"principal.attributes.level","op":"lte","value":3}`, true},
		{"gte", `{"attr":"resource.attributes.amount","op":"gte","value":1000}`, true},
		{"starts_with", `{"attr":"resource.id","op":"starts_with","value":"inv-"}`, true},
		{"cidr in", `{"attr":"context.ip","op":"cidr","value":["10.0.0.0/8"]}`, true},
		{"cidr out", `{"attr":"context.ip","op":"cidr","value":["192.168.0.0/16"]}`, false},
		{"hour_utc", `{"attr":"context.hour_utc","op":"eq","value":14}`, true},
		{"app.client_id", `{"attr":"app.client_id","op":"eq","value":"billing"}`, true},
		{"action", `{"attr":"action","op":"starts_with","value":"invoice."}`, true},
		// Object-level check: compare two attributes rather than a constant.
		{"ref owner", `{"attr":"resource.attributes.owner_id","op":"eq","ref":"principal.id"}`, true},
		{"ref mismatch", `{"attr":"resource.attributes.amount","op":"eq","ref":"principal.id"}`, false},
		{"type mismatch eq is false", `{"attr":"principal.role","op":"eq","value":1}`, false},
	}
	for _, c := range cases {
		rules := mustRules(t, `[{"id":"r","effect":"allow","actions":["*"],"when":`+c.when+`}]`)
		d := NewEngine(1, rules).Decide(in)
		if d.Allow != c.want {
			t.Errorf("%s: allow = %v, want %v", c.name, d.Allow, c.want)
		}
	}
}

func TestDecide_AuthTimeAgeAbsentWhenUnknown(t *testing.T) {
	rules := mustRules(t, `[{"id":"fresh","effect":"allow","actions":["*"],
		"when":{"attr":"principal.auth_time_age","op":"lt","value":300}}]`)
	in := adminInput("admin", "x") // AuthTime 0
	d, trace := NewEngine(1, rules).Explain(in)
	if d.Allow {
		t.Fatal("a token with no auth_time must not satisfy a freshness condition")
	}
	if len(trace) != 1 || trace[0].Result != "unknown" ||
		!reflect.DeepEqual(trace[0].Missing, []string{"principal.auth_time_age"}) {
		t.Fatalf("trace = %+v, want one unknown entry naming the missing attribute", trace)
	}
}

func TestDecide_DisabledRuleIsSkipped(t *testing.T) {
	rules := mustRules(t, `[
		{"id":"allow","effect":"allow","actions":["*"]},
		{"id":"off","effect":"deny","actions":["*"],"disabled":true}
	]`)
	if d := NewEngine(1, rules).Decide(adminInput("admin", "x")); !d.Allow {
		t.Fatalf("got %+v, want the disabled deny ignored", d)
	}
}

func TestBaseline_ValidatesAndMirrorsTheGates(t *testing.T) {
	rules := Baseline()
	if errs := Validate(rules); len(errs) > 0 {
		t.Fatalf("baseline does not validate: %v", errs)
	}
	e := NewEngine(1, rules)

	user := adminInput("user", "GET /api/admin/stats")
	user.Principal.Role = "user"
	if d := e.Decide(user); d.Allow {
		t.Error("baseline lets role=user into the admin API")
	}
	if d := e.Decide(adminInput("admin", "GET /api/admin/stats")); !d.Allow || len(d.Obligations) != 0 {
		t.Errorf("admin read: got %+v, want a plain allow", d)
	}
	if d := e.Decide(adminInput("admin", "GET /api/admin/superadmins")); d.Allow {
		t.Error("baseline lets role=admin manage superadmins")
	}
	if d := e.Decide(adminInput("superadmin", "DELETE /api/admin/superadmins/{id}")); !d.Allow ||
		!reflect.DeepEqual(d.Obligations, []string{ObligationFreshAuth}) {
		t.Errorf("superadmin delete: got %+v, want allow with require_fresh_auth", d)
	}
	pending := adminInput("admin", "GET /api/admin/stats")
	pending.Principal.MustChangePassword = true
	if d := e.Decide(pending); d.Allow || d.Rule != "password-change-pending" {
		t.Errorf("pending password change: got %+v, want deny", d)
	}
}
