package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
)

// decodeClaims returns the raw claim set of a signed JWT, so a test can assert
// on claims the typed structs deliberately do not carry (the custom ones).
func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

func enrichedTokenService(t *testing.T, namespace string) *TokenService {
	t.Helper()
	ts := newDPoPTokenService(t)
	ts.SetClaimsEnricher(NewMappingEnricher(namespace))
	return ts
}

// The mapping-resolution table: every supported source resolves to the value
// the authorization server holds, under the namespaced claim name.
func TestMappingEnricher_ResolvesEverySource(t *testing.T) {
	user := &model.User{
		ID:    7,
		Name:  "Ada Lovelace",
		Email: "ada@example.com",
		Attributes: model.JSONMap{
			"tier":     "gold",
			"seats":    float64(3),
			"beta":     true,
			"absent":   nil,
			"nested":   map[string]any{"a": "b"},
			"employee": "E-1234",
		},
	}
	app := &model.App{ID: 42, ClientID: "client-abc"}

	cases := []struct {
		name   string
		source string
		want   any
		absent bool
	}{
		{name: "tier", source: "user.attributes.tier", want: "gold"},
		{name: "seats", source: "user.attributes.seats", want: float64(3)},
		{name: "beta", source: "user.attributes.beta", want: true},
		{name: "employee", source: "user.attributes.employee", want: "E-1234"},
		{name: "email", source: model.ClaimSourceUserEmail, want: "ada@example.com"},
		{name: "name", source: model.ClaimSourceUserName, want: "Ada Lovelace"},
		{name: "uid", source: model.ClaimSourceUserID, want: "7"},
		{name: "role", source: model.ClaimSourceAppRole, want: "editor"},
		{name: "appid", source: model.ClaimSourceAppID, want: "42"},
		{name: "cid", source: model.ClaimSourceAppClientID, want: "client-abc"},
		{name: "env", source: "literal:production", want: "production"},
		// A JSON null attribute yields no claim rather than a null one.
		{name: "nil", source: "user.attributes.absent", absent: true},
		// An attribute the user does not have yields no claim.
		{name: "missing", source: "user.attributes.nope", absent: true},
	}

	mappings := model.ClaimMappings{}
	for _, c := range cases {
		mappings[c.name] = model.ClaimMapping{Source: c.source}
	}
	app.ClaimMappings = mappings

	enricher := NewMappingEnricher("https://socrate/")
	claims := enricher.CustomClaims(user, app, "editor", model.ClaimTargetAccess)

	for _, c := range cases {
		got, present := claims["https://socrate/"+c.name]
		if c.absent {
			if present {
				t.Errorf("%s (%s): expected no claim, got %v", c.name, c.source, got)
			}
			continue
		}
		if !present {
			t.Errorf("%s (%s): claim missing", c.name, c.source)
			continue
		}
		if got != c.want {
			t.Errorf("%s (%s) = %#v, want %#v", c.name, c.source, got, c.want)
		}
	}
}

// A mapping's target decides which token(s) carry the claim.
func TestMappingEnricher_TargetSelectsToken(t *testing.T) {
	user := &model.User{ID: 1, Attributes: model.JSONMap{"tier": "gold"}}
	app := &model.App{
		ClientID: "client",
		ClaimMappings: model.ClaimMappings{
			"a": {Source: "user.attributes.tier", Target: model.ClaimTargetAccess},
			"i": {Source: "user.attributes.tier", Target: model.ClaimTargetID},
			"b": {Source: "user.attributes.tier", Target: model.ClaimTargetBoth},
			// Empty target defaults to the access token.
			"d": {Source: "user.attributes.tier"},
		},
	}
	enricher := NewMappingEnricher("ns:")

	access := enricher.CustomClaims(user, app, "user", model.ClaimTargetAccess)
	id := enricher.CustomClaims(user, app, "user", model.ClaimTargetID)

	for name, wantInAccess := range map[string]bool{"a": true, "i": false, "b": true, "d": true} {
		if _, ok := access["ns:"+name]; ok != wantInAccess {
			t.Errorf("access token: claim %q present=%v, want %v", name, ok, wantInAccess)
		}
	}
	for name, wantInID := range map[string]bool{"a": false, "i": true, "b": true, "d": false} {
		if _, ok := id["ns:"+name]; ok != wantInID {
			t.Errorf("id token: claim %q present=%v, want %v", name, ok, wantInID)
		}
	}
}

// A namespace without a trailing separator gets one, so the claim name is
// always delimited from the namespace.
func TestNormalizeClaimsNamespace(t *testing.T) {
	cases := map[string]string{
		"":                     DefaultClaimsNamespace,
		"   ":                  DefaultClaimsNamespace,
		"https://acme.test":    "https://acme.test/",
		"https://acme.test/":   "https://acme.test/",
		"https://acme.test#":   "https://acme.test#",
		"urn:acme:":            "urn:acme:",
		" https://acme.test/ ": "https://acme.test/",
	}
	for in, want := range cases {
		if got := NormalizeClaimsNamespace(in); got != want {
			t.Errorf("NormalizeClaimsNamespace(%q) = %q, want %q", in, got, want)
		}
	}
}

// A mapping can never overwrite a registered or standard claim: the namespace
// keeps the names apart, and the merge refuses a collision outright.
func TestCustomClaims_CannotOverwriteRegisteredClaims(t *testing.T) {
	ts := enrichedTokenService(t, "https://socrate/")
	user := &model.User{ID: 9, TokenVersion: 3, Email: "victim@example.com"}
	app := &model.App{
		ClientID: "client",
		ClaimMappings: model.ClaimMappings{
			"sub":   {Source: "literal:attacker", Target: model.ClaimTargetBoth},
			"scope": {Source: "literal:admin", Target: model.ClaimTargetBoth},
			"iss":   {Source: "literal:https://evil.example.com", Target: model.ClaimTargetBoth},
			"role":  {Source: "literal:superadmin", Target: model.ClaimTargetBoth},
		},
	}

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	access := decodeClaims(t, set.AccessToken)
	if access["sub"] != "9" {
		t.Errorf("sub = %v, want 9 — a mapping overwrote the subject", access["sub"])
	}
	if access["scope"] != "openid" {
		t.Errorf("scope = %v, want openid", access["scope"])
	}
	if access["iss"] != "https://test.example.com" {
		t.Errorf("iss = %v, want the configured issuer", access["iss"])
	}
	if access["role"] != "user" {
		t.Errorf("role = %v, want user", access["role"])
	}
	// The mapped values are still issued — under their namespaced names.
	if access["https://socrate/sub"] != "attacker" {
		t.Errorf("namespaced sub = %v, want attacker", access["https://socrate/sub"])
	}

	// And the parsed claims are unaffected too.
	parsed, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if parsed.Subject != "9" || parsed.Role != "user" {
		t.Errorf("parsed sub/role = %q/%q, want 9/user", parsed.Subject, parsed.Role)
	}
}

// A mapping that names the enricher's own namespace prefix cannot collide with
// an already-namespaced claim either: the prefix is applied once more.
func TestCustomClaims_NamespaceIsAlwaysApplied(t *testing.T) {
	user := &model.User{ID: 1, Attributes: model.JSONMap{"x": "v"}}
	app := &model.App{
		ClientID:      "client",
		ClaimMappings: model.ClaimMappings{"https://socrate/x": {Source: "user.attributes.x"}},
	}
	claims := NewMappingEnricher("https://socrate/").CustomClaims(user, app, "user", model.ClaimTargetAccess)
	if _, ok := claims["https://socrate/https://socrate/x"]; !ok {
		t.Fatalf("claim name was not namespaced: %v", claims)
	}
}

// An oversized claim set is dropped whole — the token is still issued and still
// valid, it simply carries the standard claim set.
func TestCustomClaims_SizeCapDropsSetAndKeepsTokenSmall(t *testing.T) {
	big := strings.Repeat("x", 1024)
	user := &model.User{
		ID: 4, TokenVersion: 1,
		Attributes: model.JSONMap{"a": big, "b": big, "c": big},
	}
	app := &model.App{
		ClientID: "client",
		ClaimMappings: model.ClaimMappings{
			"a": {Source: "user.attributes.a"},
			"b": {Source: "user.attributes.b"},
			"c": {Source: "user.attributes.c"},
		},
	}

	if claims := NewMappingEnricher("").CustomClaims(user, app, "user", model.ClaimTargetAccess); claims != nil {
		t.Fatalf("oversized claim set must be dropped, got %d claims", len(claims))
	}

	ts := enrichedTokenService(t, "")
	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	if len(set.AccessToken) >= 4096 {
		t.Fatalf("access token is %d bytes, want < 4096", len(set.AccessToken))
	}
	if got := decodeClaims(t, set.AccessToken); len(got) > 16 {
		t.Fatalf("access token carries %d claims, want the standard set only", len(got))
	}
}

// A claim set just under the cap is issued, and the token stays well under 4 KB.
func TestCustomClaims_UnderCapIsIssued(t *testing.T) {
	user := &model.User{
		ID: 4, TokenVersion: 1,
		Attributes: model.JSONMap{"note": strings.Repeat("y", 512)},
	}
	app := &model.App{
		ClientID:      "client",
		ClaimMappings: model.ClaimMappings{"note": {Source: "user.attributes.note"}},
	}
	ts := enrichedTokenService(t, "https://socrate/")

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims := decodeClaims(t, set.AccessToken)
	if claims["https://socrate/note"] != strings.Repeat("y", 512) {
		t.Fatalf("mapped claim missing or wrong: %v", claims["https://socrate/note"])
	}
	if len(set.AccessToken) >= 4096 {
		t.Fatalf("access token is %d bytes, want < 4096", len(set.AccessToken))
	}
}

// With no mappings — the default for every existing client — tokens are
// byte-identical in shape to before A2: no custom claims, nothing added.
func TestCustomClaims_NoMappingsLeavesTokenUnchanged(t *testing.T) {
	ts := enrichedTokenService(t, "")
	plain := newDPoPTokenService(t)
	user := &model.User{ID: 2, TokenVersion: 1, Email: "u@example.com"}
	app := &model.App{ClientID: "client"}

	withEnricher, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	withoutEnricher, err := plain.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	a := decodeClaims(t, withEnricher.AccessToken)
	b := decodeClaims(t, withoutEnricher.AccessToken)
	// jti/iat differ between issuances; compare the claim names.
	if len(a) != len(b) {
		t.Fatalf("claim count %d != %d — the enricher changed an unmapped token", len(a), len(b))
	}
	for name := range b {
		if _, ok := a[name]; !ok {
			t.Errorf("claim %q missing with the enricher installed", name)
		}
	}
}

// A nil enricher (the zero value of TokenService) must not panic.
func TestCustomClaims_NilEnricherIsSafe(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 1, TokenVersion: 1}
	app := &model.App{
		ClientID:      "client",
		ClaimMappings: model.ClaimMappings{"tier": {Source: "literal:gold"}},
	}
	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	if claims := decodeClaims(t, set.AccessToken); claims["https://socrate/tier"] != nil {
		t.Fatalf("no enricher installed, yet a custom claim was issued")
	}
}

// A client-credentials token has no user: app-scoped and literal sources
// resolve, user-scoped ones yield nothing rather than panicking.
func TestCustomClaims_ClientCredentialsHasNoUser(t *testing.T) {
	ts := enrichedTokenService(t, "https://socrate/")
	app := &model.App{
		ID:       11,
		ClientID: "svc-client",
		ClaimMappings: model.ClaimMappings{
			"env":    {Source: "literal:production"},
			"cid":    {Source: model.ClaimSourceAppClientID},
			"mail":   {Source: model.ClaimSourceUserEmail},
			"tier":   {Source: "user.attributes.tier"},
			"whoami": {Source: model.ClaimSourceUserID},
		},
	}

	token, err := ts.GenerateClientCredentialsToken(app, "api:read")
	if err != nil {
		t.Fatalf("GenerateClientCredentialsToken: %v", err)
	}
	claims := decodeClaims(t, token)

	if claims["https://socrate/env"] != "production" {
		t.Errorf("env = %v, want production", claims["https://socrate/env"])
	}
	if claims["https://socrate/cid"] != "svc-client" {
		t.Errorf("cid = %v, want svc-client", claims["https://socrate/cid"])
	}
	for _, name := range []string{"mail", "tier", "whoami"} {
		if _, present := claims["https://socrate/"+name]; present {
			t.Errorf("user-sourced claim %q was issued on a token with no user", name)
		}
	}
	if claims["sub"] != "app:11" {
		t.Errorf("sub = %v, want app:11", claims["sub"])
	}
}

// The ID token carries id/both-targeted claims and keeps its standard ones.
func TestCustomClaims_IDToken(t *testing.T) {
	ts := enrichedTokenService(t, "https://socrate/")
	user := &model.User{ID: 3, TokenVersion: 1, Email: "id@example.com", Name: "ID User"}
	app := &model.App{
		ClientID: "client",
		ClaimMappings: model.ClaimMappings{
			"dept": {Source: "literal:eng", Target: model.ClaimTargetID},
			"only": {Source: "literal:access", Target: model.ClaimTargetAccess},
			"mail": {Source: "literal:spoofed", Target: model.ClaimTargetBoth},
			// A collision with a standard ID-token claim is namespaced away.
			"email": {Source: "literal:spoofed", Target: model.ClaimTargetID},
		},
	}

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "nonce-1", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	id := decodeClaims(t, set.IDToken)
	if id["email"] != "id@example.com" {
		t.Errorf("email = %v, want id@example.com", id["email"])
	}
	if id["https://socrate/email"] != "spoofed" {
		t.Errorf("namespaced email = %v, want spoofed", id["https://socrate/email"])
	}
	if id["https://socrate/dept"] != "eng" {
		t.Errorf("dept = %v, want eng", id["https://socrate/dept"])
	}
	if _, present := id["https://socrate/only"]; present {
		t.Errorf("access-only claim leaked into the ID token")
	}
	if id["nonce"] != "nonce-1" {
		t.Errorf("nonce = %v, want nonce-1", id["nonce"])
	}
}
