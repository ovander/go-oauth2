// Package policy is Socrate's policy decision point (A4 / EPIC-10 / RFC-005).
//
// A decision is a pure function of a rule set and an Input:
//
//	Decide({principal, app, action, resource, context}) → {allow, reason, obligations}
//
// Rules are declarative JSON — RBAC over the global and per-app roles, ABAC
// over user attributes, token facts (scopes, amr, auth_time age) and request
// context — stored as immutable, numbered versions of the whole rule set so
// every decision is attributable to exactly one version and any version can be
// restored.
//
// The package has no HTTP and no knowledge of any caller. The admin API's
// enforcement point (middleware.PolicyPEP) and, later, the decide endpoint for
// applications are both thin adapters that build an Input and act on the
// Decision.
package policy

import (
	"strings"
	"time"
)

// Mode is the rollout switch, POLICY_MODE.
type Mode string

const (
	// ModeOff consults nothing. The rule store and the admin API still work,
	// so an operator can author and simulate rules before turning anything on.
	ModeOff Mode = "off"
	// ModeShadow evaluates every request and records would-be denials and any
	// disagreement with the existing code gates, but never changes a response.
	ModeShadow Mode = "shadow"
	// ModeEnforce honours a deny. It never grants anything the code gates
	// refuse: the PDP runs in front of them, so both must allow.
	ModeEnforce Mode = "enforce"
)

// NormalizeMode maps POLICY_MODE to a Mode, falling back to off for anything
// unrecognised — a typo must never switch enforcement on.
func NormalizeMode(v string) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(v))) {
	case ModeShadow:
		return ModeShadow
	case ModeEnforce:
		return ModeEnforce
	default:
		return ModeOff
	}
}

// Effect is what a matching rule contributes.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Obligations an allow can carry. The PDP only returns them; honouring them is
// the enforcement point's job, because only it knows how to ask the caller for
// a fresh login or a second factor.
const (
	// ObligationFreshAuth requires an authentication recent enough for the
	// admin step-up window (ADMIN_ELEVATION_MAX_AGE).
	ObligationFreshAuth = "require_fresh_auth"
	// ObligationMFA requires the token's amr to show a second factor.
	ObligationMFA = "require_mfa"
)

var knownObligations = map[string]bool{
	ObligationFreshAuth: true,
	ObligationMFA:       true,
}

// Obligations lists every obligation a rule may carry.
func Obligations() []string { return []string{ObligationFreshAuth, ObligationMFA} }

// Rule is one statement of the policy. A rule applies to a request when one of
// its Actions matches the request's action and its When condition holds.
type Rule struct {
	// ID is a stable slug, unique within the rule set. It is what a decision
	// cites as its reason, so it should say what the rule is for.
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Effect      Effect `json:"effect"`
	// Actions are glob patterns over the action string. `*` matches any run
	// of characters, including none. For the admin API an action is
	// "METHOD /route/pattern", e.g. "DELETE /api/admin/apps/{id}".
	Actions []string `json:"actions"`
	// When is the condition; nil means the rule applies to every matching
	// action.
	When *Condition `json:"when,omitempty"`
	// Obligations are attached to an allow. Not meaningful on a deny.
	Obligations []string `json:"obligations,omitempty"`
	// Disabled keeps a rule in the set without evaluating it, so it can be
	// switched off without losing it.
	Disabled bool `json:"disabled,omitempty"`
}

// Condition is a node in a small boolean expression tree. Exactly one shape
// is set:
//
//	{"all": [...]}                          every child holds
//	{"any": [...]}                          at least one child holds
//	{"not": {...}}                          the child does not hold
//	{"attr": "...", "op": "...", "value": X}  compare an attribute to a constant
//	{"attr": "...", "op": "...", "ref": "..."} compare it to another attribute
//	{"attr": "...", "op": "exists"}           the attribute is present
type Condition struct {
	All   []Condition `json:"all,omitempty"`
	Any   []Condition `json:"any,omitempty"`
	Not   *Condition  `json:"not,omitempty"`
	Attr  string      `json:"attr,omitempty"`
	Op    string      `json:"op,omitempty"`
	Value any         `json:"value,omitempty"`
	Ref   string      `json:"ref,omitempty"`
}

// Input is everything a decision may look at. Nothing outside it is consulted,
// which is what makes a decision reproducible from its log row.
type Input struct {
	Principal Principal `json:"principal"`
	// App is the application the request is about, when there is one.
	App      *App     `json:"app,omitempty"`
	Action   string   `json:"action"`
	Resource Resource `json:"resource"`
	Context  Env      `json:"context"`
}

// Principal kinds.
const (
	PrincipalUser   = "user"
	PrincipalClient = "client"
)

// Principal is who is asking.
type Principal struct {
	// Kind is PrincipalUser or PrincipalClient.
	Kind     string `json:"kind"`
	ID       uint   `json:"id,omitempty"`
	Role     string `json:"role,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	// AppRole is the principal's role in Input.App, when both are known.
	AppRole    string         `json:"app_role,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Scopes     []string       `json:"scopes,omitempty"`
	AMR        []string       `json:"amr,omitempty"`
	// AuthTime is the unix time of the last interactive authentication; zero
	// when unknown, in which case principal.auth_time_age is absent rather
	// than "very large".
	AuthTime int64 `json:"auth_time,omitempty"`
	// MustChangePassword is the forced-password-change flag (users only).
	MustChangePassword bool `json:"must_change_password,omitempty"`
}

// App identifies the application a request concerns.
type App struct {
	ID       uint   `json:"id"`
	ClientID string `json:"client_id,omitempty"`
}

// Resource is what is being acted on.
type Resource struct {
	Type       string         `json:"type,omitempty"`
	ID         string         `json:"id,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Env is the request context.
type Env struct {
	IP        string `json:"ip,omitempty"`
	IPCountry string `json:"ip_country,omitempty"`
	// Now is the decision time. Zero means time.Now() at evaluation.
	Now time.Time `json:"-"`
	// Attributes carries caller-supplied context (context.attributes.<key>).
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Decision is the PDP's answer.
type Decision struct {
	Allow bool `json:"allow"`
	// Rule is the ID of the deciding rule; empty when no rule applied.
	Rule string `json:"rule,omitempty"`
	// Reason is a short machine-readable explanation, e.g. "denied_by_rule",
	// "allowed_by_rule", "no_applicable_rule".
	Reason      string   `json:"reason"`
	Obligations []string `json:"obligations,omitempty"`
	// Version is the rule-set version that produced the decision.
	Version int64 `json:"policy_version"`
}

// Decision reasons.
const (
	ReasonAllowed         = "allowed_by_rule"
	ReasonDenied          = "denied_by_rule"
	ReasonIndeterminate   = "deny_rule_indeterminate"
	ReasonNoApplicable    = "no_applicable_rule"
	ReasonPolicyUnloaded  = "policy_unavailable"
	ReasonObligationUnmet = "obligation_unmet"
)
