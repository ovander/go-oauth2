package service

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"golang.org/x/crypto/bcrypt"
)

// #336: application-defined (namespaced) scopes, valid only for a client that
// registers them in its allowed_scopes.

func TestAppScope_Grammar(t *testing.T) {
	ns32 := "a" + strings.Repeat("b", 31)
	name64 := "c" + strings.Repeat("d", 63)
	cases := []struct {
		scope string
		want  bool
	}{
		{"swingdrift:worker", true},
		{"a:b", true},
		{"app-1:read.v2", true},
		{"billing:invoices_read", true},
		{"x9:y-z.w_v", true},
		{ns32 + ":" + name64, true}, // the 97-character maximum
		{"", false},
		{"swingdrift", false},                  // no namespace
		{":worker", false},                     // empty namespace
		{"swingdrift:", false},                 // empty name
		{"Swingdrift:worker", false},           // upper case
		{"swingdrift:Worker", false},           // upper case
		{"1app:x", false},                      // namespace must start with a letter
		{"-app:x", false},                      // namespace must start with a letter
		{"app:1x", false},                      // name must start with a letter
		{"app:.x", false},                      // name must start with a letter
		{"app_x:y", false},                     // '_' not allowed in a namespace
		{"app.x:y", false},                     // '.' not allowed in a namespace
		{"a:b:c", false},                       // exactly one colon
		{ns32 + "x:y", false},                  // namespace too long
		{"a:" + name64 + "x", false},           // name too long
		{"app:wo rker", false},                 // space
		{"app :x", false},                      // space
		{"app:x\n", false},                     // control character
		{"app:<script>", false},                // HTML metacharacters
		{"app:x\"y", false},                    // quote
		{"app:x'y", false},                     // quote
		{"app:x&y", false},                     // ampersand
		{"app:x/y", false},                     // slash
		{"app:x*", false},                      // wildcard
		{"app:\u00e9", false},                  // non-ASCII
		{"app:x\\y", false},                    // backslash
		{"swingdrift:worker ", false},          // trailing space
		{"swingdrift:worker\u0000", false},     // NUL
		{"swingdrift:worker\u200b", false},     // zero-width space
		{"\u0455wingdrift:worker", false},      // Cyrillic homoglyph
		{"swingdrift:worker%20admin", false},   // percent-encoding
		{"swingdrift:worker\tadmin", false},    // tab
		{"swingdrift:x;admin", false},          // separator
		{"swingdrift:x,admin", false},          // separator
		{"swingdrift:x+admin", false},          // separator
		{"swingdrift:x\u00a0admin", false},     // non-breaking space
		{"swingdrift:x\radmin", false},         // carriage return
		{"swingdrift:x\u2028admin", false},     // line separator
		{"swingdrift:x\u0085admin", false},     // next line
		{"swingdrift:x\u3000admin", false},     // ideographic space
		{"swingdrift:x\u00adadmin", false},     // soft hyphen
		{"swingdrift:x\ufeffadmin", false},     // BOM
		{"swingdrift:x\u202eadmin", false},     // right-to-left override
		{"swingdrift:x\u0301admin", false},     // combining mark
		{"swingdrift:x\U0001F600admin", false}, // emoji
	}
	for _, tc := range cases {
		if got := isAppScope(tc.scope); got != tc.want {
			t.Errorf("isAppScope(%q) = %v, want %v", tc.scope, got, tc.want)
		}
	}
}

// Every character the grammar admits must be an RFC 6749 §3.3 scope-token
// character (NQCHAR = %x21 / %x23-5B / %x5D-7E).
func TestAppScope_GrammarIsSubsetOfRFC6749ScopeToken(t *testing.T) {
	nqchar := func(c byte) bool { return c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E) }
	for c := 0; c < 256; c++ {
		for _, s := range []string{"ns:a" + string(rune(c)), "n" + string(rune(c)) + ":a"} {
			if !appScopePattern.MatchString(s) {
				continue
			}
			for i := 0; i < len(s); i++ {
				if !nqchar(s[i]) {
					t.Fatalf("grammar admits %q, whose byte %#x is not an RFC 6749 scope-token character", s, s[i])
				}
			}
		}
	}
}

func TestAppScope_ReservedNamespaces(t *testing.T) {
	for _, s := range []string{
		"monitoring:evil", "monitoring:read2", "admin:x", "socrate:x", "openid:x", "oidc:x",
		"oauth:x", "oauth2:x", "api:x", "email:x", "profile:x",
	} {
		if isAppScope(s) {
			t.Errorf("isAppScope(%q) = true, want false (reserved namespace)", s)
		}
		if err := validateScopeNames([]string{s}); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("validateScopeNames(%q) = %v, want ErrInvalidScope", s, err)
		}
	}
	// A global scope is never an app scope, though it stays registrable.
	for g := range validScopes {
		if isAppScope(g) {
			t.Errorf("global scope %q classified as an app scope", g)
		}
	}
}

// The reserved list is derived from validScopes: a future global "foo:bar"
// reserves "foo" without anyone remembering to add it.
func TestAppScope_ReservedNamespacesDerivedFromGlobalScopes(t *testing.T) {
	validScopes["futurens:read"] = true
	defer delete(validScopes, "futurens:read")
	reserved := buildReservedScopeNamespaces()
	for _, ns := range []string{"futurens", "monitoring", "openid", "email", "profile", "offline_access", "api", "admin", "socrate", "oidc", "oauth", "oauth2"} {
		if !reserved[ns] {
			t.Errorf("namespace %q not reserved", ns)
		}
	}
	if reserved["swingdrift"] {
		t.Error("an application namespace must not be reserved")
	}
}

func TestAppScope_ValidateScopeNames(t *testing.T) {
	cases := []struct {
		names []string
		ok    bool
	}{
		{[]string{"openid", "monitoring:read", "admin"}, true}, // globals as before
		{[]string{"api", "swingdrift:worker"}, true},
		{[]string{"swingdrift:worker", "swingdrift:worker"}, true}, // duplicates tolerated
		{[]string{"bogus"}, false},
		{[]string{""}, false},
		{[]string{"swingdrift:Worker"}, false},
		{[]string{"api", "monitoring:evil"}, false},
		{[]string{"swingdrift:worker admin"}, false}, // one entry smuggling two scopes
		{[]string{" swingdrift:worker"}, false},
	}
	for _, tc := range cases {
		err := validateScopeNames(tc.names)
		if tc.ok && err != nil {
			t.Errorf("validateScopeNames(%q) = %v, want nil", tc.names, err)
		}
		if !tc.ok && (!errors.Is(err, ErrInvalidScope) || !strings.Contains(err.Error(), "unknown scope")) {
			t.Errorf("validateScopeNames(%q) = %v, want ErrInvalidScope 'unknown scope'", tc.names, err)
		}
	}
}

func TestAppScope_ModelRegistersScope(t *testing.T) {
	app := &model.App{}
	if app.RegistersScope("swingdrift:worker") {
		t.Fatal("an empty policy must register nothing")
	}
	app.AllowedScopes = model.StringArray{"api", "swingdrift:worker"}
	if !app.RegistersScope("swingdrift:worker") || app.RegistersScope("swingdrift:other") || app.RegistersScope("swingdrift") {
		t.Fatal("RegistersScope must match an entry verbatim")
	}
}

// multiAppRepo serves several clients by client_id.
type multiAppRepo struct {
	crit02AppRepo
	apps map[string]*model.App
}

func (r *multiAppRepo) FindByClientID(_ context.Context, clientID string) (*model.App, error) {
	if a, ok := r.apps[clientID]; ok {
		return a, nil
	}
	return nil, errors.New("not found")
}

const appScopeSecret = "correct-secret"

// appScopeService returns a service whose clients are "a" (registers
// swingdrift:worker), "b" (registers only globals), "c" (empty policy) and
// "poisoned" (allowed_scopes written around the admin API with reserved names).
func appScopeService(t *testing.T, mode string) (*oauthService, map[string]*model.App) {
	t.Helper()
	svc, _ := newHigh04Service(t, newMemUsedTokenRepo())
	svc.scopePolicyMode = mode
	// Minimum bcrypt cost: CheckClientSecret honours the hash's own cost, and
	// the production cost (12) makes dozens of grants too slow under -race.
	hash, err := bcrypt.GenerateFromPassword([]byte(appScopeSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id uint, clientID string, allowed ...string) *model.App {
		return &model.App{ID: id, ClientID: clientID, Active: true, ClientSecretHash: string(hash),
			RedirectURIs: []string{"https://app.example/cb"}, AllowedScopes: model.StringArray(allowed)}
	}
	apps := map[string]*model.App{
		"a":        mk(1, "a", "api", "openid", "offline_access", "swingdrift:worker"),
		"b":        mk(2, "b", "api", "openid"),
		"c":        mk(3, "c"),
		"poisoned": mk(4, "poisoned", "api", "admin:x", "monitoring:evil", "Swingdrift:worker"),
	}
	svc.appRepo = &multiAppRepo{apps: apps}
	return svc, apps
}

func TestAppScope_ClientCredentials(t *testing.T) {
	for _, mode := range []string{"off", "observe", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			svc, _ := appScopeService(t, mode)
			cases := []struct {
				client, scope string
				ok            bool
			}{
				{"a", "swingdrift:worker", true},
				{"a", "api swingdrift:worker", true},
				{"a", "swingdrift:worker api", true},
				{"a", "swingdrift:other", false},         // not registered
				{"a", "swingdrift:Worker", false},        // malformed
				{"a", "swingdrift:worker  api", false},   // empty token
				{"b", "swingdrift:worker", false},        // registered on another client only
				{"b", "api swingdrift:worker", false},    // ...even mixed with a valid global
				{"c", "swingdrift:worker", false},        // an empty policy registers nothing
				{"poisoned", "admin:x", false},           // reserved, even if stored
				{"poisoned", "monitoring:evil", false},   // reserved, even if stored
				{"poisoned", "Swingdrift:worker", false}, // malformed, even if stored
				{"poisoned", "api monitoring:evil", false},
			}
			for _, tc := range cases {
				resp, err := svc.Token(context.Background(), ccReq(tc.scope), tc.client, appScopeSecret)
				if !tc.ok {
					if !errors.Is(err, ErrInvalidScope) {
						t.Errorf("client %s scope %q: got %v, want ErrInvalidScope", tc.client, tc.scope, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("client %s scope %q: %v", tc.client, tc.scope, err)
				}
				if resp.Scope != tc.scope {
					t.Errorf("response scope = %q, want %q", resp.Scope, tc.scope)
				}
				claims, verr := svc.tokenService.VerifyAccessToken(resp.AccessToken)
				if verr != nil {
					t.Fatalf("verify: %v", verr)
				}
				// RFC 9068 §2.2.3: issued unchanged in the space-separated claim.
				if claims.Scope != tc.scope || claims.Subject != "app:1" {
					t.Errorf("claims scope=%q sub=%q, want %q and app:1", claims.Scope, claims.Subject, tc.scope)
				}
				// RFC 7662: introspection reports it too.
				ir, ierr := svc.Introspect(context.Background(), resp.AccessToken, tc.client)
				if ierr != nil || !ir.Active || ir.Scope != tc.scope {
					t.Errorf("introspect = %+v (%v), want active with scope %q", ir, ierr, tc.scope)
				}
			}
		})
	}
}

// Registering an app scope never lets a client obtain a global scope it could
// not obtain before: the global rules (and the A1 policy) are unchanged.
func TestAppScope_NoGlobalEscalation(t *testing.T) {
	svc, _ := appScopeService(t, "enforce")
	for _, scope := range []string{"admin", "monitoring:write", "swingdrift:worker admin"} {
		if _, err := svc.Token(context.Background(), ccReq(scope), "a", appScopeSecret); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("enforce, scope %q: got %v, want ErrInvalidScope", scope, err)
		}
	}
	// off mode keeps today's behaviour for globals, identical with or without
	// an app scope registered.
	svc, apps := appScopeService(t, "off")
	_, withApp := svc.Token(context.Background(), ccReq("admin"), "a", appScopeSecret)
	apps["a"].AllowedScopes = model.StringArray{"api", "openid", "offline_access"}
	_, without := svc.Token(context.Background(), ccReq("admin"), "a", appScopeSecret)
	if (withApp == nil) != (without == nil) {
		t.Errorf("registering an app scope changed a global scope's outcome: %v vs %v", withApp, without)
	}
}

const appScopeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func appScopeAuthorize(svc *oauthService, clientID, scope string) (string, error) {
	return svc.Authorize(context.Background(), dto.AuthorizeRequest{
		ClientID: clientID, RedirectURI: "https://app.example/cb",
		ResponseType: "code", Scope: scope, State: "s",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256",
		MaxAge: -1,
	}, 42)
}

func appScopeRedeem(svc *oauthService, clientID, code string) (*dto.TokenResponse, error) {
	return svc.Token(context.Background(), dto.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example/cb",
		CodeVerifier: appScopeVerifier,
	}, clientID, appScopeSecret)
}

func TestAppScope_AuthorizationCodeAndRefresh(t *testing.T) {
	for _, mode := range []string{"off", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			svc, apps := appScopeService(t, mode)
			const scope = "openid offline_access swingdrift:worker"

			if _, err := appScopeAuthorize(svc, "b", scope); !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("authorize on a client without the scope: got %v, want ErrInvalidScope", err)
			}
			code, err := appScopeAuthorize(svc, "a", scope)
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			resp, err := appScopeRedeem(svc, "a", code)
			if err != nil {
				t.Fatalf("redeem: %v", err)
			}
			claims, err := svc.tokenService.VerifyAccessToken(resp.AccessToken)
			if err != nil || claims.Scope != scope || claims.Subject != "42" {
				t.Fatalf("access token scope=%q sub=%q (%v), want %q and 42", claims.Scope, claims.Subject, err, scope)
			}
			if resp.RefreshToken == "" {
				t.Fatal("expected a refresh token (offline_access)")
			}

			// Refresh keeps the scope while the client registers it.
			r2, err := svc.Token(context.Background(), refreshReq(resp.RefreshToken), "a", appScopeSecret)
			if err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if c2, _ := svc.tokenService.VerifyAccessToken(r2.AccessToken); c2 == nil || c2.Scope != scope {
				t.Fatalf("refreshed scope = %v, want %q", c2, scope)
			}

			// Unregistered: the next refresh is refused, whatever the mode.
			apps["a"].AllowedScopes = model.StringArray{"api", "openid", "offline_access"}
			if _, err := svc.Token(context.Background(), refreshReq(r2.RefreshToken), "a", appScopeSecret); !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("refresh after unregistering: got %v, want ErrInvalidScope", err)
			}

			// A code issued while registered is not redeemable after removal.
			apps["a"].AllowedScopes = model.StringArray{"api", "openid", "offline_access", "swingdrift:worker"}
			code, err = appScopeAuthorize(svc, "a", scope)
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			apps["a"].AllowedScopes = model.StringArray{"api", "openid", "offline_access"}
			if _, err := appScopeRedeem(svc, "a", code); !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("redeem after unregistering: got %v, want ErrInvalidScope", err)
			}
		})
	}
}

// Tokens without app scopes (everything issued before #336) refresh as before.
func TestAppScope_RefreshWithoutAppScopesUnchanged(t *testing.T) {
	svc, rt := newHigh04Service(t, newMemUsedTokenRepo())
	if _, err := svc.Token(context.Background(), refreshReq(rt), "test-client", ""); err != nil {
		t.Fatalf("legacy refresh: %v", err)
	}
	if err := checkRegisteredAppScopes(nil, "openid email profile offline_access api admin monitoring:read read write"); err != nil {
		t.Fatalf("non-namespaced and global scopes must pass: %v", err)
	}
	if err := checkRegisteredAppScopes(nil, "openid swingdrift:worker"); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("app scope without a client: got %v, want ErrInvalidScope", err)
	}
}

func TestAppScope_TokenExchange(t *testing.T) {
	registered := &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowedScopes: model.StringArray{"swingdrift:worker"}}
	svc, _, ts := newShadowExchangeSvc(t, registered)
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	subj := mintToken(t, ts, 100, "read swingdrift:worker")
	actor := mintToken(t, ts, 200, "read")

	resp, err := svc.ExchangeToken(context.Background(), exForm(subj, actor, "swingdrift:worker", "https://api.example.com"), "c", "")
	if err != nil {
		t.Fatalf("exchange with a registered app scope: %v", err)
	}
	if claims, _ := ts.VerifyAccessToken(resp.AccessToken); claims == nil || claims.Scope != "swingdrift:worker" {
		t.Fatalf("exchanged scope = %v, want swingdrift:worker", claims)
	}

	// The requesting client does not register it: refused, explicitly or by default scope.
	unregistered := &model.App{ID: 8, ClientID: "c", AllowTokenExchange: true}
	svc, audit, ts := newShadowExchangeSvc(t, unregistered)
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	subj = mintToken(t, ts, 100, "read swingdrift:worker")
	actor = mintToken(t, ts, 200, "read")
	for _, reqScope := range []string{"swingdrift:worker", ""} {
		if _, err := svc.ExchangeToken(context.Background(), exForm(subj, actor, reqScope, "https://api.example.com"), "c", ""); !errors.Is(err, ErrInvalidScope) {
			t.Fatalf("exchange scope %q without registration: got %v, want ErrInvalidScope", reqScope, err)
		}
		if audit.last.Details["outcome"] != "denied" {
			t.Errorf("audit outcome = %v, want denied", audit.last.Details["outcome"])
		}
	}
	// A plain downscope that drops the app scope still works.
	if _, err := svc.ExchangeToken(context.Background(), exForm(subj, actor, "read", "https://api.example.com"), "c", ""); err != nil {
		t.Fatalf("downscope without the app scope: %v", err)
	}

	// Shadow mode: invisible to the client, recorded in the audit.
	svc.tokenExchangeMode = TokenExchangeModeShadow
	if _, err := svc.ExchangeToken(context.Background(), exForm(subj, actor, "swingdrift:worker", "https://api.example.com"), "c", ""); !errors.Is(err, ErrInvalidGrantType) {
		t.Fatalf("shadow: got %v, want ErrInvalidGrantType", err)
	}
	if reason, _ := audit.last.Details["deny_reason"].(string); !strings.Contains(reason, "swingdrift:worker") {
		t.Errorf("shadow deny_reason = %q, want it to name the scope", reason)
	}
}

// The consent page shows an app scope verbatim, escaped; anything outside the
// grammar is not echoed into the list.
func TestAppScope_ConsentRendersSafely(t *testing.T) {
	got := scopeDescriptions("openid swingdrift:worker admin:x a:<script> monitoring:evil")
	want := []string{"Verify your identity", "Use the application permission swingdrift:worker"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("scopeDescriptions = %q, want %q", got, want)
	}

	rr := httptest.NewRecorder()
	ts := NewTemplateService()
	if err := ts.RenderConsent(rr, ConsentPageData{
		AppName: "Swingdrift", ClientID: "a", RedirectURI: "https://app.example/cb", ResponseType: "code",
		Scope: `openid swingdrift:worker "><script>alert(1)</script>`, State: "s", MaxAge: -1,
	}); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := rr.Body.Bytes()
	if !bytes.Contains(body, []byte("<li>Use the application permission swingdrift:worker</li>")) {
		t.Error("consent page does not list the application permission")
	}
	if bytes.Contains(body, []byte("<script>alert(1)</script>")) {
		t.Error("consent page echoes unescaped markup")
	}
}

// Discovery keeps advertising the global scopes only.
func TestAppScope_DiscoveryUnchanged(t *testing.T) {
	svc, _ := appScopeService(t, "enforce")
	got := svc.GetOpenIDConfiguration("https://auth.example.com").ScopesSupported
	want := []string{"openid", "email", "profile", "offline_access", "api"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("scopes_supported = %v, want %v", got, want)
	}
}
