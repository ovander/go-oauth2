package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/metrics"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// PolicyPEP is the admin API's policy enforcement point (A4). It consults the
// PDP on every authenticated admin request, in front of the existing code
// gates (RequireGlobalAdmin, RequireRole, RequireFreshAuth, …):
//
//   - POLICY_MODE=shadow: the decision never changes the response. The request
//     runs through the code gates as before, and the PEP compares what the
//     policy would have done with what the code actually did — a would-be
//     denial, or any disagreement, is written to the decision log.
//   - POLICY_MODE=enforce: a deny (or an allow whose obligation is unmet) is
//     answered with 403 before the code gates run. An allow does NOT bypass
//     them: the request still has to pass every gate, so enforcing a policy can
//     only ever remove access, never grant it.
//
// Retiring a code gate in favour of its rule is a separate, later decision,
// made once the divergence counter for it has been zero for a release.
type PolicyPEP struct {
	pdp             *policy.Service
	elevationMaxAge time.Duration
	countryOf       func(ip string) string
}

// NewPolicyPEP returns an enforcement point. elevationMaxAge is the admin
// step-up window (ADMIN_ELEVATION_MAX_AGE), used to honour the
// require_fresh_auth obligation exactly as RequireFreshAuth does. A nil pdp
// yields a pass-through.
func NewPolicyPEP(pdp *policy.Service, elevationMaxAge time.Duration) *PolicyPEP {
	return &PolicyPEP{pdp: pdp, elevationMaxAge: elevationMaxAge}
}

// SetCountryLookup supplies context.ip_country. Without it (no GeoIP
// database) the attribute is always absent — so a rule that tests it is
// unknown, which under deny-overrides means a deny rule on country denies.
func (p *PolicyPEP) SetCountryLookup(fn func(ip string) string) {
	if p != nil {
		p.countryOf = fn
	}
}

// Admin routes the PEP never gates. The policy editor must stay reachable
// under any policy — otherwise one bad rule in enforce mode locks out the only
// place it can be fixed — and so must the two routes an admin needs to
// recover their own session. All three remain behind the code gates.
var pepExemptSuffixes = []string{"/elevate", "/change-password"}

const pepExemptPolicyTree = "/policy"

// Middleware returns the enforcement middleware for the sub-router mounted at
// prefix. routes must be that sub-router: the PEP resolves the matched route
// pattern through it before routing completes, which is what turns a request
// into an action like "DELETE /api/admin/apps/{id}".
//
// It must run after AuthMiddleware.
func (p *PolicyPEP) Middleware(prefix string, routes chi.Routes) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if p == nil || p.pdp == nil || p.pdp.Mode() == policy.ModeOff {
			return next
		}
		mode := p.pdp.Mode()

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rctx := chi.RouteContext(r.Context())
			if rctx == nil {
				next.ServeHTTP(w, r)
				return
			}
			matched := chi.NewRouteContext()
			pattern := routes.Find(matched, r.Method, rctx.RoutePath)
			if pattern == "" {
				// No such route: the router answers 404/405 itself and
				// there is nothing to authorise.
				next.ServeHTTP(w, r)
				return
			}
			pattern = normalizePattern(pattern)
			if isPEPExempt(pattern) {
				next.ServeHTTP(w, r)
				return
			}

			user, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
			claims, _ := r.Context().Value(contextkeys.JWTClaimsKey).(*auth.AccessTokenClaims)
			if user == nil {
				next.ServeHTTP(w, r) // AuthMiddleware has already refused this
				return
			}

			fullPattern := prefix + pattern
			in := policy.Input{
				Principal: principalFor(user, claims),
				Action:    r.Method + " " + fullPattern,
				Resource: policy.Resource{
					Type: resourceType(pattern),
					ID:   matched.URLParam("id"),
				},
				Context: policy.Env{IP: GetClientIP(r)},
			}
			if p.countryOf != nil && in.Context.IP != "" {
				in.Context.IPCountry = p.countryOf(in.Context.IP)
			}

			d, err := p.pdp.Decide(r.Context(), in)
			unmet := ""
			if err == nil && d.Allow {
				unmet = p.unmetObligation(d.Obligations, claims)
			}
			pdpAllow := err == nil && d.Allow && unmet == ""

			rec := &policy.DecisionRecord{
				CorrelationID: GetCorrelationID(r.Context()),
				Source:        policy.SourceAdminPEP,
				Mode:          string(mode),
				Enforced:      mode == policy.ModeEnforce,
				Allow:         pdpAllow,
				Action:        in.Action,
				Rule:          d.Rule,
				Reason:        d.Reason,
				PolicyVersion: d.Version,
				PrincipalKind: in.Principal.Kind,
				PrincipalID:   &user.ID,
				ClientID:      in.Principal.ClientID,
				ResourceType:  in.Resource.Type,
				ResourceID:    in.Resource.ID,
				IPAddress:     in.Context.IP,
			}
			if unmet != "" {
				rec.Reason = policy.ReasonObligationUnmet + ":" + unmet
			}

			outcome := "allow"
			switch {
			case err != nil:
				outcome = "error"
			case !pdpAllow:
				outcome = "deny"
			}
			metrics.PolicyDecision(policy.SourceAdminPEP, string(mode), outcome)

			if mode == policy.ModeEnforce && !pdpAllow {
				status, code := http.StatusForbidden, "policy_denied"
				switch {
				case err != nil:
					// Nothing to decide with. Fail closed; the policy
					// editor itself is exempt, so this is recoverable.
					status, code = http.StatusServiceUnavailable, "policy_unavailable"
				case unmet == policy.ObligationFreshAuth:
					// Same code RequireFreshAuth returns, so the consoles'
					// existing step-up flow handles it unchanged.
					code = "elevation_required"
				case unmet == policy.ObligationMFA:
					code = "mfa_required"
				}
				rec.StatusCode = status
				p.pdp.Record(r.Context(), rec)
				writePolicyError(w, code, status)
				return
			}

			// Shadow, or an enforced allow: the code gates decide the
			// response. Watch what they do.
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				if rv := recover(); rv != nil {
					// A panic comes from a handler — no gate panics — so the
					// request got past every gate. Record, then re-panic so
					// Recoverer answers exactly as it would have.
					p.observe(r.Context(), rec, err, pdpAllow, http.StatusInternalServerError, true)
					panic(rv)
				}
			}()
			next.ServeHTTP(ww, r)
			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}
			p.observe(r.Context(), rec, err, pdpAllow, status, false)
		})
	}
}

// observe compares the PDP's decision with what the code did and records the
// decision if it was a denial or a disagreement.
//
// reachedHandler is set when the request is known to have passed every gate
// regardless of its final status.
func (p *PolicyPEP) observe(ctx context.Context, rec *policy.DecisionRecord, err error, pdpAllow bool, status int, reachedHandler bool) {
	rec.StatusCode = status
	if err != nil {
		// No decision to compare. Logged once per request so an outage in
		// shadow mode is visible without being mistaken for divergence.
		p.pdp.Record(ctx, rec)
		return
	}

	codeAllowed := reachedHandler || (status != http.StatusUnauthorized && status != http.StatusForbidden)
	switch {
	case !pdpAllow && codeAllowed:
		rec.Divergence = policy.DivergencePDPStricter
	case pdpAllow && !codeAllowed:
		rec.Divergence = policy.DivergencePDPLooser
	}
	if rec.Divergence != "" {
		metrics.PolicyDivergence(rec.Source, rec.Divergence)
		logger.WithFields(logger.Fields{
			"action":         rec.Action,
			"rule":           rec.Rule,
			"divergence":     rec.Divergence,
			"status":         status,
			"policy_version": rec.PolicyVersion,
			"correlation_id": rec.CorrelationID,
		}).Warn("A4: policy and code gates disagree")
	}
	if !pdpAllow || rec.Divergence != "" {
		p.pdp.Record(ctx, rec)
	}
}

// PolicyActions walks a sub-router and returns the action string the PEP would
// build for each of its routes, split into the gated and the exempt ones.
func PolicyActions(prefix string, routes chi.Routes) (actions, exempt []string) {
	seen := map[string]bool{}
	_ = chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		pattern := normalizePattern(route)
		action := method + " " + prefix + pattern
		if seen[action] {
			return nil
		}
		seen[action] = true
		if isPEPExempt(pattern) {
			exempt = append(exempt, action)
		} else {
			actions = append(actions, action)
		}
		return nil
	})
	return actions, exempt
}

// writePolicyError answers a policy refusal. Unlike writeAuthError it sets no
// WWW-Authenticate challenge: the token is fine, the request is not allowed.
func writePolicyError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: code})
}

// unmetObligation returns the first obligation the request does not satisfy,
// or "".
//
// The fresh-auth window is RequireFreshAuth's, so a zero window disables the
// check here as it does there.
func (p *PolicyPEP) unmetObligation(obligations []string, claims *auth.AccessTokenClaims) string {
	var (
		amr      []string
		authTime int64
	)
	if claims != nil {
		amr, authTime = claims.Amr, claims.AuthTime
	}
	return policy.UnmetObligation(obligations, amr, authTime, p.elevationMaxAge, time.Now())
}

// principalFor builds the policy principal from the authenticated user and the
// token that carried them.
func principalFor(user *model.User, claims *auth.AccessTokenClaims) policy.Principal {
	pr := policy.Principal{
		Kind:               policy.PrincipalUser,
		ID:                 user.ID,
		Role:               string(user.Role),
		Attributes:         map[string]any(user.Attributes),
		Scopes:             []string{},
		AMR:                []string{},
		MustChangePassword: user.MustChangePassword,
	}
	if claims != nil {
		pr.Scopes = strings.Fields(claims.Scope)
		if claims.Amr != nil {
			pr.AMR = claims.Amr
		}
		pr.AuthTime = claims.AuthTime
		if len(claims.Audience) > 0 {
			pr.ClientID = claims.Audience[0]
		}
	}
	return pr
}

// normalizePattern drops chi's trailing slash ("/apps/{id}/" → "/apps/{id}")
// so that an action does not depend on how a route happened to be nested.
func normalizePattern(p string) string {
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	if p == "" {
		p = "/"
	}
	return p
}

func isPEPExempt(pattern string) bool {
	if pattern == pepExemptPolicyTree || strings.HasPrefix(pattern, pepExemptPolicyTree+"/") {
		return true
	}
	return slices.Contains(pepExemptSuffixes, pattern)
}

// resourceType is the first literal segment of the route: "/apps/{id}" → "apps".
func resourceType(pattern string) string {
	seg, _, _ := strings.Cut(strings.TrimPrefix(pattern, "/"), "/")
	if strings.HasPrefix(seg, "{") {
		return ""
	}
	return seg
}
