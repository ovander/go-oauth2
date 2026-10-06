package auth

import (
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
)

// The enricher reports the mapped claims a token did not get: a user attribute
// the user lacks (what an operator can fix), and a set dropped for its size.
func TestMappingEnricher_ReportsProblems(t *testing.T) {
	var got []ClaimIssueProblem
	e := NewMappingEnricher("")
	e.SetProblemReporter(func(p ClaimIssueProblem) { got = append(got, p) })

	app := &model.App{ID: 3, ClientID: "lakebridge-portal", ClaimMappings: model.ClaimMappings{
		"tenant_id": {Source: "user.attributes.tenant_id", Target: model.ClaimTargetAccess},
		"title":     {Source: "user.name", Target: model.ClaimTargetAccess},
		"plan":      {Source: "literal:gold", Target: model.ClaimTargetAccess},
	}}
	user := &model.User{ID: 42} // no attributes, no name

	claims := e.CustomClaims(user, app, "user", model.ClaimTargetAccess)
	if _, ok := claims["https://socrate/tenant_id"]; ok || claims["https://socrate/plan"] != "gold" {
		t.Fatalf("claims = %v", claims)
	}
	if len(got) != 1 {
		t.Fatalf("want one problem (the missing attribute, not the empty name), got %+v", got)
	}
	want := ClaimIssueProblem{Kind: ClaimProblemMissing, UserID: 42, AppID: 3, ClientID: "lakebridge-portal",
		Claim: "tenant_id", Source: "user.attributes.tenant_id", Target: model.ClaimTargetAccess}
	if got[0] != want {
		t.Errorf("problem = %+v, want %+v", got[0], want)
	}

	// Present attribute: nothing to report.
	got = nil
	user.Attributes = model.JSONMap{"tenant_id": "0b6f…"}
	e.CustomClaims(user, app, "user", model.ClaimTargetAccess)
	if len(got) != 0 {
		t.Errorf("unexpected problems: %+v", got)
	}

	// Oversized set: dropped whole, reported once with its size.
	got = nil
	user.Attributes = model.JSONMap{"tenant_id": strings.Repeat("x", MaxCustomClaimsBytes)}
	if c := e.CustomClaims(user, app, "user", model.ClaimTargetAccess); c != nil {
		t.Fatalf("an oversized set must be dropped, got %v", c)
	}
	if len(got) != 1 || got[0].Kind != ClaimProblemDropped || got[0].UserID != 42 || got[0].Size <= MaxCustomClaimsBytes {
		t.Errorf("dropped problem = %+v", got)
	}
}

// Without a reporter (the default), problems are only logged, as before.
func TestMappingEnricher_NoReporterIsSafe(t *testing.T) {
	e := NewMappingEnricher("")
	app := &model.App{ID: 3, ClientID: "c", ClaimMappings: model.ClaimMappings{
		"tenant_id": {Source: "user.attributes.tenant_id", Target: model.ClaimTargetAccess},
	}}
	if c := e.CustomClaims(&model.User{ID: 1}, app, "user", model.ClaimTargetAccess); c != nil {
		t.Errorf("claims = %v, want none", c)
	}
}
