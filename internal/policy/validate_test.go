package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func validateJSON(t *testing.T, raw string) []ValidationError {
	t.Helper()
	var rules []Rule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return Validate(rules)
}

func TestValidate_RejectsMistakesThatWouldSilentlyNeverMatch(t *testing.T) {
	cases := []struct {
		name, rules, wantPath, wantMsg string
	}{
		{"bad id", `[{"id":"Bad ID","effect":"allow","actions":["*"]}]`, "id", "characters"},
		{"duplicate id", `[{"id":"a","effect":"allow","actions":["*"]},{"id":"a","effect":"deny","actions":["*"]}]`, "id", "duplicate"},
		{"bad effect", `[{"id":"a","effect":"permit","actions":["*"]}]`, "effect", "allow"},
		{"no actions", `[{"id":"a","effect":"allow","actions":[]}]`, "actions", "at least one"},
		{"unknown obligation", `[{"id":"a","effect":"allow","actions":["*"],"obligations":["sudo"]}]`, "obligations[0]", "unknown obligation"},
		{"obligation on deny", `[{"id":"a","effect":"deny","actions":["*"],"obligations":["require_mfa"]}]`, "obligations", "allow rule"},
		{"unknown attribute (typo)", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.rol","op":"eq","value":"admin"}}]`, "when.attr", "unknown attribute"},
		{"unknown op", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.role","op":"like","value":"a"}}]`, "when.op", "unknown operator"},
		{"eq on a list", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.scopes","op":"eq","value":"admin"}}]`, "when.op", "is a list"},
		{"contains on a string", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.role","op":"contains","value":"adm"}}]`, "when.op", "not a list"},
		{"ordering on a string", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.role","op":"lt","value":3}}]`, "when.op", "is a string"},
		{"lt needs a number", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.auth_time_age","op":"lt","value":"300"}}]`, "when.value", "number"},
		{"in needs a list", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.role","op":"in","value":"admin"}}]`, "when.value", "list"},
		{"bad cidr", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"context.ip","op":"cidr","value":["10.0.0.0/33"]}}]`, "when.value[0]", "CIDR"},
		{"value and ref", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.role","op":"eq","value":"x","ref":"principal.kind"}}]`, "when", "exactly one"},
		{"neither value nor ref", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.role","op":"eq"}}]`, "when", "exactly one"},
		{"bad ref", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.role","op":"eq","ref":"principal.nope"}}]`, "when.ref", "unknown attribute"},
		{"exists with value", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.role","op":"exists","value":1}}]`, "when", "neither"},
		{"two shapes", `[{"id":"a","effect":"allow","actions":["*"],"when":{"all":[{"attr":"principal.role","op":"exists"}],"attr":"principal.kind","op":"exists"}}]`, "when", "exactly one of"},
		{"empty all", `[{"id":"a","effect":"allow","actions":["*"],"when":{"all":[]}}]`, "when", "exactly one of"},
		{"bool with lt", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.must_change_password","op":"lt","value":1}}]`, "when.op", "boolean"},
		{"bad map key", `[{"id":"a","effect":"allow","actions":["*"],"when":{"attr":"principal.attributes.a b","op":"exists"}}]`, "when.attr", "unknown attribute"},
		{"nested error path", `[{"id":"a","effect":"allow","actions":["*"],"when":{"all":[{"attr":"principal.role","op":"exists"},{"not":{"attr":"x","op":"exists"}}]}}]`, "when.all[1].not.attr", "unknown attribute"},
	}
	for _, c := range cases {
		errs := validateJSON(t, c.rules)
		found := false
		for _, e := range errs {
			if e.Path == c.wantPath && strings.Contains(e.Message, c.wantMsg) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want an error at %q mentioning %q, got %v", c.name, c.wantPath, c.wantMsg, errs)
		}
	}
}

func TestValidate_ReportsEveryError(t *testing.T) {
	errs := validateJSON(t, `[
		{"id":"a","effect":"nope","actions":[]},
		{"id":"b","effect":"allow","actions":["*"],"when":{"attr":"bogus","op":"eq","value":1}}
	]`)
	if len(errs) < 3 {
		t.Fatalf("got %d errors, want all three reported at once: %v", len(errs), errs)
	}
}

func TestValidate_Bounds(t *testing.T) {
	// Depth.
	c := &Condition{Attr: "principal.role", Op: opExists}
	for i := 0; i < maxConditionDepth+1; i++ {
		c = &Condition{Not: c}
	}
	if errs := Validate([]Rule{{ID: "deep", Effect: EffectAllow, Actions: []string{"*"}, When: c}}); len(errs) == 0 {
		t.Error("a condition nested past the depth limit was accepted")
	}

	// Rule count.
	rules := make([]Rule, MaxRules+1)
	for i := range rules {
		rules[i] = Rule{ID: fmt.Sprintf("r%d", i), Effect: EffectAllow, Actions: []string{"*"}}
	}
	if errs := Validate(rules); len(errs) == 0 {
		t.Error("a rule set over MaxRules was accepted")
	}
}

func TestValidate_AcceptsAWellFormedSet(t *testing.T) {
	errs := validateJSON(t, `[
		{"id":"owner-edits","effect":"allow","actions":["doc.edit"],
		 "when":{"all":[
			{"attr":"resource.attributes.owner_id","op":"eq","ref":"principal.id"},
			{"any":[{"attr":"principal.amr","op":"contains","value":"mfa"},{"attr":"context.ip","op":"cidr","value":["10.0.0.0/8"]}]},
			{"not":{"attr":"principal.must_change_password","op":"eq","value":true}}
		 ]},
		 "obligations":["require_fresh_auth"]}
	]`)
	if len(errs) > 0 {
		t.Fatalf("well-formed set rejected: %v", errs)
	}
}
