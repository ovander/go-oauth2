package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// A mapping is accepted in both the object form and the bare-string shorthand,
// and the shorthand defaults to the access token.
func TestClaimMapping_UnmarshalJSON(t *testing.T) {
	var m ClaimMappings
	input := `{
		"tier":  "user.attributes.tier",
		"dept":  {"source": "user.attributes.dept", "target": "both"},
		"plain": {"source": "user.email"}
	}`
	if err := json.Unmarshal([]byte(input), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if m["tier"].Source != "user.attributes.tier" || m["tier"].Target != ClaimTargetAccess {
		t.Errorf("shorthand = %+v, want source user.attributes.tier target access", m["tier"])
	}
	if m["dept"].Target != ClaimTargetBoth {
		t.Errorf("object target = %q, want both", m["dept"].Target)
	}
	if m["plain"].Target != ClaimTargetAccess {
		t.Errorf("object with no target = %q, want access", m["plain"].Target)
	}
}

func TestClaimMapping_WritesTo(t *testing.T) {
	cases := []struct {
		target       string
		access, idOK bool
	}{
		{ClaimTargetAccess, true, false},
		{ClaimTargetID, false, true},
		{ClaimTargetBoth, true, true},
		{"", true, false},
	}
	for _, c := range cases {
		m := ClaimMapping{Source: "user.email", Target: c.target}
		if got := m.WritesTo(ClaimTargetAccess); got != c.access {
			t.Errorf("target %q WritesTo(access) = %v, want %v", c.target, got, c.access)
		}
		if got := m.WritesTo(ClaimTargetID); got != c.idOK {
			t.Errorf("target %q WritesTo(id) = %v, want %v", c.target, got, c.idOK)
		}
	}
}

// A bad mapping is refused at write time, so it can never reach issuance.
func TestValidateClaimMappings(t *testing.T) {
	valid := []ClaimMappings{
		{},
		{"tier": {Source: "user.attributes.tier"}},
		{"mail": {Source: ClaimSourceUserEmail, Target: ClaimTargetBoth}},
		{"who": {Source: ClaimSourceUserID, Target: ClaimTargetID}},
		{"role": {Source: ClaimSourceAppRole}},
		{"cid": {Source: ClaimSourceAppClientID}},
		{"aid": {Source: ClaimSourceAppID}},
		{"env": {Source: "literal:prod"}},
	}
	for i, m := range valid {
		if err := ValidateClaimMappings(m); err != nil {
			t.Errorf("valid[%d] %v: unexpected error %v", i, m, err)
		}
	}

	invalid := map[string]ClaimMappings{
		"unknown source":     {"x": {Source: "user.password"}},
		"empty source":       {"x": {Source: ""}},
		"attribute-less":     {"x": {Source: "user.attributes."}},
		"unknown target":     {"x": {Source: "user.email", Target: "refresh"}},
		"empty name":         {"": {Source: "user.email"}},
		"whitespace in name": {"a b": {Source: "user.email"}},
		"quote in name":      {`a"b`: {Source: "user.email"}},
		"name too long":      {strings.Repeat("n", MaxClaimName+1): {Source: "user.email"}},
	}
	for name, m := range invalid {
		if err := ValidateClaimMappings(m); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

// An attribute source is a map lookup, not a path: a traversal-looking key is
// accepted as a mapping (it names a key nothing will ever have) and simply
// resolves to no claim. Documented here so the absence of a path check is a
// decision rather than an oversight.
func TestValidateClaimMappings_AttributeKeyIsNotAPath(t *testing.T) {
	m := ClaimMappings{"x": {Source: ClaimSourceUserAttrPrefix + "../../secret"}}
	if err := ValidateClaimMappings(m); err != nil {
		t.Fatalf("attribute key is a map key, not a path: %v", err)
	}
}

// Names() is stable, which is what makes the issuance-time size decision
// deterministic.
func TestClaimMappings_NamesSorted(t *testing.T) {
	m := ClaimMappings{"c": {}, "a": {}, "b": {}}
	got := m.Names()
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("Names() = %v, want [a b c]", got)
	}
}

// Both jsonb types survive a database round trip, and an empty value is stored
// as `{}` rather than NULL (the columns are NOT NULL).
func TestJSONMapAndClaimMappings_RoundTrip(t *testing.T) {
	attrs := JSONMap{"tier": "gold", "seats": float64(3), "beta": true}
	stored, err := attrs.Value()
	if err != nil {
		t.Fatalf("JSONMap.Value: %v", err)
	}
	var back JSONMap
	if err := back.Scan(stored); err != nil {
		t.Fatalf("JSONMap.Scan: %v", err)
	}
	if len(back) != 3 || back["tier"] != "gold" || back["seats"] != float64(3) || back["beta"] != true {
		t.Fatalf("round trip = %#v, want the original map", back)
	}

	mappings := ClaimMappings{"tier": {Source: "user.attributes.tier", Target: ClaimTargetBoth}}
	storedM, err := mappings.Value()
	if err != nil {
		t.Fatalf("ClaimMappings.Value: %v", err)
	}
	var backM ClaimMappings
	if err := backM.Scan(storedM); err != nil {
		t.Fatalf("ClaimMappings.Scan: %v", err)
	}
	if backM["tier"].Source != "user.attributes.tier" || backM["tier"].Target != ClaimTargetBoth {
		t.Fatalf("round trip = %#v, want the original mapping", backM)
	}

	// Empty values, NULL columns and byte slices.
	for _, c := range []struct {
		name string
		src  any
	}{{"nil", nil}, {"empty bytes", []byte("")}, {"empty object", []byte("{}")}} {
		var m JSONMap
		if err := m.Scan(c.src); err != nil {
			t.Errorf("JSONMap.Scan(%s): %v", c.name, err)
		}
		if m == nil || len(m) != 0 {
			t.Errorf("JSONMap.Scan(%s) = %#v, want an empty non-nil map", c.name, m)
		}

		var cm ClaimMappings
		if err := cm.Scan(c.src); err != nil {
			t.Errorf("ClaimMappings.Scan(%s): %v", c.name, err)
		}
		if cm == nil || len(cm) != 0 {
			t.Errorf("ClaimMappings.Scan(%s) = %#v, want an empty non-nil map", c.name, cm)
		}
	}

	if v, _ := JSONMap(nil).Value(); v != "{}" {
		t.Errorf("nil JSONMap stored as %v, want {}", v)
	}
	if v, _ := ClaimMappings(nil).Value(); v != "{}" {
		t.Errorf("nil ClaimMappings stored as %v, want {}", v)
	}

	// Garbage in the column is an error, not a silent empty map.
	var bad JSONMap
	if err := bad.Scan([]byte("not json")); err == nil {
		t.Errorf("JSONMap.Scan(garbage): expected an error")
	}
	if err := bad.Scan(42); err == nil {
		t.Errorf("JSONMap.Scan(int): expected an error")
	}
}
