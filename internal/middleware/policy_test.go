package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/policy"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

type pepFixture struct {
	store *policy.MemoryStore
	pdp   *policy.Service
}

func newPEPFixture(t *testing.T, mode policy.Mode, rules []policy.Rule) *pepFixture {
	t.Helper()
	store := policy.NewMemoryStore()
	pdp := policy.NewService(store, mode, time.Nanosecond)
	if rules != nil {
		if _, err := pdp.Save(context.Background(), 0, rules, "", 1); err != nil {
			t.Fatal(err)
		}
	}
	return &pepFixture{store: store, pdp: pdp}
}

func (f *pepFixture) decisions(t *testing.T) []policy.DecisionRecord {
	t.Helper()
	d, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{})
	return d
}

// pepRouter mounts a small admin tree behind the PEP, with the user and
// claims injected the way AuthMiddleware would.
func pepRouter(pep *PolicyPEP, user *model.User, claims *auth.AccessTokenClaims) http.Handler {
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	r := chi.NewRouter()
	r.Route("/api/admin", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				ctx := req.Context()
				if user != nil {
					ctx = context.WithValue(ctx, contextkeys.CurrentUserKey, user)
					ctx = context.WithValue(ctx, contextkeys.UserIDKey, user.ID)
				}
				if claims != nil {
					ctx = context.WithValue(ctx, contextkeys.JWTClaimsKey, claims)
				}
				next.ServeHTTP(w, req.WithContext(ctx))
			})
		})
		r.Use(pep.Middleware("/api/admin", r))
		r.Get("/stats", ok)
		r.Route("/apps/{id}", func(r chi.Router) { r.Delete("/", ok) })
		r.Get("/code-refuses", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
		r.Get("/boom", func(http.ResponseWriter, *http.Request) { panic("handler bug") })
		r.Put("/policy", ok)
		r.Get("/policy/versions/{version}", ok)
		r.Post("/elevate", ok)
		r.Post("/change-password", ok)
	})
	return r
}

func serve(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
	return rr
}

var (
	pepAdmin  = &model.User{ID: 7, Role: model.UserRoleAdmin}
	denyAll   = []policy.Rule{{ID: "deny-all", Effect: policy.EffectDeny, Actions: []string{"*"}}}
	allowAll  = []policy.Rule{{ID: "allow-all", Effect: policy.EffectAllow, Actions: []string{"*"}}}
	freshNow  = func() *auth.AccessTokenClaims { return &auth.AccessTokenClaims{AuthTime: time.Now().Unix()} }
	pepPrefix = "/api/admin"
)

func TestPolicyPEP_OffAndNil_ArePassThrough(t *testing.T) {
	f := newPEPFixture(t, policy.ModeOff, denyAll)
	for name, pep := range map[string]*PolicyPEP{
		"mode off": NewPolicyPEP(f.pdp, time.Minute),
		"nil pep":  nil,
		"nil pdp":  NewPolicyPEP(nil, time.Minute),
	} {
		if rr := serve(pepRouter(pep, pepAdmin, freshNow()), http.MethodGet, "/api/admin/stats"); rr.Code != http.StatusOK {
			t.Errorf("%s: deny-all policy changed the response: %d", name, rr.Code)
		}
	}
	if len(f.decisions(t)) != 0 {
		t.Error("mode off recorded decisions")
	}
}

func TestPolicyPEP_Enforce_DenyIs403_WithoutABearerChallenge(t *testing.T) {
	f := newPEPFixture(t, policy.ModeEnforce, denyAll)
	rr := serve(pepRouter(NewPolicyPEP(f.pdp, time.Minute), pepAdmin, freshNow()), http.MethodDelete, "/api/admin/apps/42/")
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"policy_denied"`) {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	// The token is fine; a WWW-Authenticate invalid_token challenge would
	// send a client off to re-authenticate for nothing.
	if h := rr.Header().Get("WWW-Authenticate"); h != "" {
		t.Errorf("WWW-Authenticate = %q on a policy denial", h)
	}
	d := f.decisions(t)
	if len(d) != 1 || d[0].Action != "DELETE /api/admin/apps/{id}" || d[0].ResourceType != "apps" ||
		d[0].ResourceID != "42" || !d[0].Enforced || d[0].Rule != "deny-all" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestPolicyPEP_ExemptRoutes_AreNeverConsulted(t *testing.T) {
	f := newPEPFixture(t, policy.ModeEnforce, denyAll)
	h := pepRouter(NewPolicyPEP(f.pdp, time.Minute), pepAdmin, freshNow())
	for _, rt := range [][2]string{
		{http.MethodPut, "/api/admin/policy"},
		{http.MethodGet, "/api/admin/policy/versions/3"},
		{http.MethodPost, "/api/admin/elevate"},
		{http.MethodPost, "/api/admin/change-password"},
	} {
		if rr := serve(h, rt[0], rt[1]); rr.Code != http.StatusOK {
			t.Errorf("%s %s under deny-all → %d, want 200", rt[0], rt[1], rr.Code)
		}
	}
	if len(f.decisions(t)) != 0 {
		t.Errorf("exempt routes were evaluated: %+v", f.decisions(t))
	}
}

func TestPolicyPEP_UnmatchedRouteAndNoUser_PassThrough(t *testing.T) {
	f := newPEPFixture(t, policy.ModeEnforce, denyAll)
	pep := NewPolicyPEP(f.pdp, time.Minute)
	if rr := serve(pepRouter(pep, pepAdmin, freshNow()), http.MethodGet, "/api/admin/nope"); rr.Code != http.StatusNotFound {
		t.Errorf("unmatched route → %d, want the router's 404", rr.Code)
	}
	if rr := serve(pepRouter(pep, nil, nil), http.MethodGet, "/api/admin/stats"); rr.Code != http.StatusOK {
		t.Errorf("no user → %d; the PEP should defer to AuthMiddleware", rr.Code)
	}
}

func TestPolicyPEP_Shadow_RecordsDivergenceBothWays_WithoutChangingResponses(t *testing.T) {
	// PDP stricter than the code.
	f := newPEPFixture(t, policy.ModeShadow, denyAll)
	h := pepRouter(NewPolicyPEP(f.pdp, time.Minute), pepAdmin, freshNow())
	if rr := serve(h, http.MethodGet, "/api/admin/stats"); rr.Code != http.StatusOK {
		t.Fatalf("shadow changed the response: %d", rr.Code)
	}
	d := f.decisions(t)
	if len(d) != 1 || d[0].Divergence != policy.DivergencePDPStricter || d[0].Enforced || d[0].StatusCode != 200 {
		t.Fatalf("stricter: %+v", d)
	}

	// PDP looser than the code.
	f = newPEPFixture(t, policy.ModeShadow, allowAll)
	h = pepRouter(NewPolicyPEP(f.pdp, time.Minute), pepAdmin, freshNow())
	if rr := serve(h, http.MethodGet, "/api/admin/code-refuses"); rr.Code != http.StatusForbidden {
		t.Fatalf("shadow changed the response: %d", rr.Code)
	}
	d = f.decisions(t)
	if len(d) != 1 || d[0].Divergence != policy.DivergencePDPLooser || !d[0].Allow {
		t.Fatalf("looser: %+v", d)
	}

	// Agreement on an allow is not logged (metrics only).
	f = newPEPFixture(t, policy.ModeShadow, allowAll)
	serve(pepRouter(NewPolicyPEP(f.pdp, time.Minute), pepAdmin, freshNow()), http.MethodGet, "/api/admin/stats")
	if len(f.decisions(t)) != 0 {
		t.Fatalf("an agreeing allow was logged: %+v", f.decisions(t))
	}
}

func TestPolicyPEP_Shadow_HandlerPanic_IsRecordedAndReRaised(t *testing.T) {
	f := newPEPFixture(t, policy.ModeShadow, denyAll)
	h := pepRouter(NewPolicyPEP(f.pdp, time.Minute), pepAdmin, freshNow())

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the handler's panic was swallowed")
			}
		}()
		serve(h, http.MethodGet, "/api/admin/boom")
	}()
	d := f.decisions(t)
	if len(d) != 1 || d[0].Divergence != policy.DivergencePDPStricter || d[0].StatusCode != http.StatusInternalServerError {
		t.Fatalf("panic path decision = %+v; reaching a handler means the gates let it through", d)
	}
}

func TestPolicyPEP_NoPolicy_ShadowProceeds_EnforceFailsClosed(t *testing.T) {
	f := newPEPFixture(t, policy.ModeShadow, nil)
	if rr := serve(pepRouter(NewPolicyPEP(f.pdp, time.Minute), pepAdmin, freshNow()), http.MethodGet, "/api/admin/stats"); rr.Code != http.StatusOK {
		t.Fatalf("shadow with no policy → %d", rr.Code)
	}
	d := f.decisions(t)
	if len(d) != 1 || d[0].Reason != policy.ReasonPolicyUnloaded || d[0].Divergence != "" {
		t.Fatalf("shadow/no policy: %+v — an outage must be visible but not counted as divergence", d)
	}

	f = newPEPFixture(t, policy.ModeEnforce, nil)
	rr := serve(pepRouter(NewPolicyPEP(f.pdp, time.Minute), pepAdmin, freshNow()), http.MethodGet, "/api/admin/stats")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "policy_unavailable") {
		t.Fatalf("enforce/no policy → %d %s", rr.Code, rr.Body.String())
	}
}

func TestPolicyPEP_FreshAuthObligation_MirrorsRequireFreshAuth(t *testing.T) {
	rules := []policy.Rule{{ID: "fresh", Effect: policy.EffectAllow, Actions: []string{"*"},
		Obligations: []string{policy.ObligationFreshAuth}}}
	stale := &auth.AccessTokenClaims{AuthTime: time.Now().Add(-time.Hour).Unix()}

	f := newPEPFixture(t, policy.ModeEnforce, rules)
	rr := serve(pepRouter(NewPolicyPEP(f.pdp, 5*time.Minute), pepAdmin, stale), http.MethodGet, "/api/admin/stats")
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "elevation_required") {
		t.Fatalf("stale → %d %s, want 403 elevation_required", rr.Code, rr.Body.String())
	}
	if d := f.decisions(t); len(d) != 1 || d[0].Reason != policy.ReasonObligationUnmet+":"+policy.ObligationFreshAuth {
		t.Fatalf("decision = %+v", d)
	}
	if rr := serve(pepRouter(NewPolicyPEP(f.pdp, 5*time.Minute), pepAdmin, freshNow()), http.MethodGet, "/api/admin/stats"); rr.Code != http.StatusOK {
		t.Fatalf("fresh → %d", rr.Code)
	}
	noAuthTime := &auth.AccessTokenClaims{}
	if rr := serve(pepRouter(NewPolicyPEP(f.pdp, 5*time.Minute), pepAdmin, noAuthTime), http.MethodGet, "/api/admin/stats"); rr.Code != http.StatusForbidden {
		t.Fatalf("no auth_time → %d, want 403 (recency cannot be proven)", rr.Code)
	}
	// A zero window disables RequireFreshAuth, so it disables the obligation.
	if rr := serve(pepRouter(NewPolicyPEP(f.pdp, 0), pepAdmin, stale), http.MethodGet, "/api/admin/stats"); rr.Code != http.StatusOK {
		t.Fatalf("zero window → %d, want the obligation waived", rr.Code)
	}
}

func TestPolicyPEP_UnknownObligation_IsUnmet(t *testing.T) {
	p := NewPolicyPEP(nil, time.Minute)
	if got := p.unmetObligation([]string{"require_hardware_key"}, freshNow()); got != "require_hardware_key" {
		t.Fatalf("unknown obligation reported as %q; one this PEP cannot honour must not be dropped", got)
	}
}

func TestPrincipalFor(t *testing.T) {
	u := &model.User{ID: 3, Role: model.UserRoleSuperadmin, MustChangePassword: true,
		Attributes: model.JSONMap{"tenant": "acme"}}
	claims := &auth.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{"admin-console", "https://api"}},
		Scope:            "openid admin", Amr: []string{"pwd", "mfa"}, AuthTime: 1234,
	}
	got := principalFor(u, claims)
	want := policy.Principal{Kind: policy.PrincipalUser, ID: 3, Role: "superadmin", ClientID: "admin-console",
		Attributes: map[string]any{"tenant": "acme"}, Scopes: []string{"openid", "admin"},
		AMR: []string{"pwd", "mfa"}, AuthTime: 1234, MustChangePassword: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	// Without claims the lists are present-but-empty, not absent: "has no
	// scopes" is a fact, and conditions on it must evaluate, not go unknown.
	bare := principalFor(&model.User{ID: 1, Role: model.UserRoleAdmin}, nil)
	if bare.Scopes == nil || bare.AMR == nil {
		t.Fatalf("bare principal lists are nil: %+v", bare)
	}
}

func TestPolicyActions_SplitsExempt(t *testing.T) {
	r := chi.NewRouter()
	h := func(http.ResponseWriter, *http.Request) {}
	r.Get("/stats", h)
	r.Route("/apps/{id}", func(r chi.Router) { r.Delete("/", h) })
	r.Put("/policy", h)
	r.Get("/policy/catalogue", h)
	r.Post("/elevate", h)

	actions, exempt := PolicyActions(pepPrefix, r)
	wantActions := map[string]bool{"GET /api/admin/stats": true, "DELETE /api/admin/apps/{id}": true}
	wantExempt := map[string]bool{"PUT /api/admin/policy": true, "GET /api/admin/policy/catalogue": true, "POST /api/admin/elevate": true}
	if len(actions) != len(wantActions) || len(exempt) != len(wantExempt) {
		t.Fatalf("actions=%v exempt=%v", actions, exempt)
	}
	for _, a := range actions {
		if !wantActions[a] {
			t.Errorf("unexpected action %q", a)
		}
	}
	for _, a := range exempt {
		if !wantExempt[a] {
			t.Errorf("unexpected exempt action %q", a)
		}
	}
}

func TestResourceTypeAndNormalizePattern(t *testing.T) {
	for in, want := range map[string]string{"/apps/{id}/": "/apps/{id}", "/": "/", "/stats": "/stats"} {
		if got := normalizePattern(in); got != want {
			t.Errorf("normalizePattern(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"/apps/{id}": "apps", "/stats": "stats", "/{id}": "", "/": ""} {
		if got := resourceType(in); got != want {
			t.Errorf("resourceType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPolicyPEP_CountryLookup(t *testing.T) {
	rules := []policy.Rule{
		{ID: "all", Effect: policy.EffectAllow, Actions: []string{"*"}},
		{ID: "embargo", Effect: policy.EffectDeny, Actions: []string{"*"},
			When: &policy.Condition{Attr: "context.ip_country", Op: "in", Value: []any{"XX"}}},
	}
	f := newPEPFixture(t, policy.ModeEnforce, rules)
	get := func(pep *PolicyPEP) int {
		return serve(pepRouter(pep, pepAdmin, freshNow()), http.MethodGet, "/api/admin/stats").Code
	}

	be := NewPolicyPEP(f.pdp, time.Minute)
	be.SetCountryLookup(func(string) string { return "BE" })
	if code := get(be); code != http.StatusOK {
		t.Errorf("BE → %d, want 200", code)
	}
	xx := NewPolicyPEP(f.pdp, time.Minute)
	xx.SetCountryLookup(func(string) string { return "XX" })
	if code := get(xx); code != http.StatusForbidden {
		t.Errorf("XX → %d, want 403", code)
	}
	// No GeoIP database: the country is unknown, and a deny rule that depends
	// on it fails closed. Documented, and visible in shadow before enforcing.
	if code := get(NewPolicyPEP(f.pdp, time.Minute)); code != http.StatusForbidden {
		t.Errorf("no lookup → %d, want 403 (indeterminate deny)", code)
	}
}
