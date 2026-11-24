// Package http — A4 policy enforcement point on the app-management routes,
// /api/apps/{app_id}/* (#395).
//
// The same properties as on the admin API, over the real router: shadow mode
// never changes a response and the seeded baseline agrees with RequireAppAccess
// and RequireAppAdmin for every kind of caller; enforce with the baseline
// answers exactly as the code does; a rule can refuse what the code allows; and
// the decision carries the application and the caller's role in it.
package http

import (
	"context"
	"errors"
	nethttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// appPEPRoles is a UserAppRoleRepository holding one role per (user, app).
type appPEPRoles struct {
	repository.UserAppRoleRepository
	roles map[[2]uint]model.AppRole
}

func (r *appPEPRoles) FindByUserAndApp(_ context.Context, userID, appID uint) (*model.UserAppRole, error) {
	if role, ok := r.roles[[2]uint{userID, appID}]; ok {
		return &model.UserAppRole{UserID: userID, AppID: appID, Role: role}, nil
	}
	return nil, errors.New("record not found")
}

// The app the callers are tested against, and another one.
const appPEPApp, appPEPOtherApp = 5, 6

func appPEPCallers() []struct {
	name string
	user *model.User
} {
	u := func(id uint, role model.UserRole) *model.User {
		return &model.User{ID: id, Email: "u@example.com", Role: role, IsVerified: true}
	}
	return []struct {
		name string
		user *model.User
	}{
		{"app admin", u(20, model.UserRoleUser)},
		{"app member", u(21, model.UserRoleUser)},
		{"non-member", u(22, model.UserRoleUser)},
		{"global admin", u(7, model.UserRoleAdmin)},
		{"superadmin", u(1, model.UserRoleSuperadmin)},
	}
}

func appPEPRoleRepo() *appPEPRoles {
	return &appPEPRoles{roles: map[[2]uint]model.AppRole{
		{20, appPEPApp}: model.AppRoleAdmin,
		{21, appPEPApp}: model.AppRoleUser,
	}}
}

// appPEPRouter builds the real admin router (which carries /api/apps) with a
// role store; s nil means no PEP.
func appPEPRouter(t *testing.T, ts *auth.TokenService, user *model.User, s *a4Setup) nethttp.Handler {
	t.Helper()
	cfg := RouterConfig{AdminElevationMaxAge: a4MaxAge}
	if s != nil {
		cfg.PolicyPEP = middleware.NewPolicyPEP(s.pdp, a4MaxAge)
		cfg.PolicyHandler = s.ph
	}
	adminAuth := handler.NewAdminAuthHandler(nil, &p31UserService{user: user})
	return newAdminRouter(nil, adminAuth, nil, nil, nil, nil, nil, nil, nil, nil,
		ts, &p31UserRepo{user: user}, nil, appPEPRoleRepo(), nil, cfg)
}

// appPEPRequests are every app-management route, on the tested app and on
// another one.
func appPEPRequests() [][2]string {
	var out [][2]string
	for _, app := range []string{"5", "6"} {
		base := "/api/apps/" + app
		out = append(out,
			[2]string{"GET", base + "/users"},
			[2]string{"POST", base + "/users"},
			[2]string{"GET", base + "/users/9"},
			[2]string{"PUT", base + "/users/9"},
			[2]string{"DELETE", base + "/users/9"},
			[2]string{"POST", base + "/users/9/resend-verification"},
			[2]string{"POST", base + "/users/9/reset-password"},
			[2]string{"GET", base + "/logs"},
		)
	}
	return out
}

func TestA4App_Shadow_NeverChangesAResponse_AndBaselineHasNoDivergence(t *testing.T) {
	ts := p31TokenService(t)
	for _, c := range appPEPCallers() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := a4PDP(t, policy.ModeShadow, nil)
			ref := appPEPRouter(t, ts, c.user, nil)
			shadow := appPEPRouter(t, ts, c.user, s)
			tok := a4Mint(t, ts, c.user, time.Now())
			for _, rq := range appPEPRequests() {
				want := a4Do(ref, rq[0], rq[1], tok)
				if got := a4Do(shadow, rq[0], rq[1], tok); got != want {
					t.Errorf("%s %s: shadow %d %s, off %d %s", rq[0], rq[1], got.code, got.body, want.code, want.body)
				}
			}
			decisions, _ := s.store.Decisions(context.Background(), policy.DecisionFilter{})
			for _, d := range decisions {
				if d.Divergence != "" {
					t.Errorf("divergence %s on %s (rule %q, reason %s, status %d)", d.Divergence, d.Action, d.Rule, d.Reason, d.StatusCode)
				}
				if d.Source != policy.SourceAppPEP {
					t.Errorf("decision on %s has source %q, want %q", d.Action, d.Source, policy.SourceAppPEP)
				}
			}
		})
	}
}

func TestA4App_Enforce_WithBaseline_MatchesTheCodeGates(t *testing.T) {
	ts := p31TokenService(t)
	for _, c := range appPEPCallers() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ref := appPEPRouter(t, ts, c.user, nil)
			enforced := appPEPRouter(t, ts, c.user, a4PDP(t, policy.ModeEnforce, nil))
			tok := a4Mint(t, ts, c.user, time.Now())
			for _, rq := range appPEPRequests() {
				want := a4Do(ref, rq[0], rq[1], tok)
				got := a4Do(enforced, rq[0], rq[1], tok)
				// The PDP refuses with policy_denied where the code says
				// forbidden: the same refusal, another body.
				if got.code != want.code {
					t.Errorf("%s %s: enforce %d %s, off %d %s", rq[0], rq[1], got.code, got.body, want.code, want.body)
				}
			}
		})
	}
}

// A rule can take away what the code allows, on one app route: proof that the
// enforcement point is in front of the code gates there.
func TestA4App_Enforce_CanRefuseWhatTheCodeAllows(t *testing.T) {
	ts := p31TokenService(t)
	rules := append(policy.Baseline(), policy.Rule{
		ID:      "no-app-user-deletion",
		Effect:  policy.EffectDeny,
		Actions: []string{"DELETE " + policy.AppPrefix + "/users/{user_id}"},
	})
	s := a4PDP(t, policy.ModeEnforce, rules)
	appAdmin := appPEPCallers()[0].user
	h := appPEPRouter(t, ts, appAdmin, s)
	tok := a4Mint(t, ts, appAdmin, time.Now())

	if r := a4Do(h, "DELETE", "/api/apps/5/users/9", tok); r.code != nethttp.StatusForbidden || r.body != `{"error":"policy_denied"}` {
		t.Fatalf("denied route: %d %s, want 403 policy_denied", r.code, r.body)
	}
	if r := a4Do(h, "GET", "/api/apps/5/users/9", tok); r.code == nethttp.StatusForbidden {
		t.Fatalf("another route was refused too: %d %s", r.code, r.body)
	}
	decisions, _ := s.store.Decisions(context.Background(), policy.DecisionFilter{})
	var found bool
	for _, d := range decisions {
		if d.Action == "DELETE /api/apps/{app_id}/users/{user_id}" && d.Rule == "no-app-user-deletion" {
			found = true
			if d.ResourceType != "users" || d.ResourceID != "9" || d.Source != policy.SourceAppPEP || !d.Enforced {
				t.Errorf("decision record: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("the refusal was not recorded: %+v", decisions)
	}
}

// The decision sees the application and the caller's role in it, resolved
// server-side: a rule on principal.app_role and input.app works.
func TestA4App_InputCarriesTheAppAndTheAppRole(t *testing.T) {
	ts := p31TokenService(t)
	rules := append(policy.Baseline(), policy.Rule{
		ID:      "logs-only-for-app-5-admins",
		Effect:  policy.EffectDeny,
		Actions: []string{"GET " + policy.AppPrefix + "/logs"},
		When: &policy.Condition{Not: &policy.Condition{All: []policy.Condition{
			{Attr: "principal.app_role", Op: "eq", Value: "admin"},
			{Attr: "app.id", Op: "eq", Value: float64(appPEPApp)},
		}}},
	})
	for _, c := range []struct {
		caller int
		path   string
		want   int
	}{
		{0, "/api/apps/5/logs", nethttp.StatusInternalServerError}, // app admin of 5: reaches the (nil) handler
		{3, "/api/apps/5/logs", nethttp.StatusForbidden},           // global admin, no app role: the rule refuses
	} {
		user := appPEPCallers()[c.caller].user
		h := appPEPRouter(t, ts, user, a4PDP(t, policy.ModeEnforce, rules))
		if r := a4Do(h, "GET", c.path, a4Mint(t, ts, user, time.Now())); r.code != c.want {
			t.Errorf("%s GET %s: %d %s, want %d", appPEPCallers()[c.caller].name, c.path, r.code, r.body, c.want)
		}
	}
}

// The catalogue lists the app actions next to the admin ones.
func TestA4App_CatalogueListsTheAppActions(t *testing.T) {
	ts := p31TokenService(t)
	sa := appPEPCallers()[4].user
	s := a4PDP(t, policy.ModeOff, nil)
	h := appPEPRouter(t, ts, sa, s)
	r := a4Do(h, "GET", "/api/admin/policy/catalogue", a4Mint(t, ts, sa, time.Now()))
	if r.code != nethttp.StatusOK {
		t.Fatalf("catalogue: %d %s", r.code, r.body)
	}
	for _, want := range []string{
		`"GET /api/apps/{app_id}/logs"`,
		`"DELETE /api/apps/{app_id}/users/{user_id}"`,
		`"POST /api/apps/{app_id}/users/{user_id}/reset-password"`,
	} {
		if !strings.Contains(r.body, want) {
			t.Errorf("catalogue misses %s: %s", want, r.body)
		}
	}
}
