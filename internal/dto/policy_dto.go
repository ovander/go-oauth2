package dto

import (
	"time"

	"github.com/ovander/go-oauth2/internal/policy"
)

// SavePolicyRequest replaces the rule set (A4). BaseVersion must be the
// version the editor loaded; a save from a stale base is refused with 409
// rather than silently overwriting someone else's change.
type SavePolicyRequest struct {
	BaseVersion int64         `json:"base_version"`
	Rules       []policy.Rule `json:"rules"`
	Note        string        `json:"note,omitempty"`
}

// ValidatePolicyRequest checks a draft rule set without saving it.
type ValidatePolicyRequest struct {
	Rules []policy.Rule `json:"rules"`
}

// RestorePolicyRequest saves an earlier version's rules as a new version.
type RestorePolicyRequest struct {
	BaseVersion int64 `json:"base_version"`
}

// SimulatePolicyRequest evaluates an input with a per-rule trace — against
// Rules when given (a draft), otherwise against the current version. At pins
// the evaluation time for time-dependent conditions.
type SimulatePolicyRequest struct {
	Input policy.Input  `json:"input"`
	Rules []policy.Rule `json:"rules,omitempty"`
	At    *time.Time    `json:"at,omitempty"`
}

// SimulatePolicyResponse is the decision and how each rule contributed.
type SimulatePolicyResponse struct {
	Decision policy.Decision     `json:"decision"`
	Trace    []policy.TraceEntry `json:"trace"`
}

// PolicyResponse is a stored version plus the mode it is running under.
type PolicyResponse struct {
	*policy.Version
	Mode string `json:"mode"`
}

// PolicyValidationResponse lists every problem in a rule set.
type PolicyValidationResponse struct {
	Error  string                   `json:"error"`
	Errors []policy.ValidationError `json:"errors"`
}

// PolicyCatalogueResponse is what an editor needs to offer choices rather
// than free text: every admin action, attribute, operator and obligation.
type PolicyCatalogueResponse struct {
	Mode          string   `json:"mode"`
	AdminActions  []string `json:"admin_actions"`
	ExemptActions []string `json:"exempt_actions"`
	Attributes    []string `json:"attributes"`
	AttributeMaps []string `json:"attribute_maps"`
	Operators     []string `json:"operators"`
	Obligations   []string `json:"obligations"`
}

// PolicyDecideRequest is an application's question to the PDP (A4 part 2).
// The calling application is taken from its client-credentials token, never
// from the body, and the subject is resolved server-side: an application can
// describe the resource and the request context, but not who the user is or
// what they hold.
type PolicyDecideRequest struct {
	// Subject is the user the decision is about. Omitted: the application
	// itself is the principal (kind "client").
	Subject  *PolicySubject      `json:"subject,omitempty"`
	Action   string              `json:"action"`
	Resource policy.Resource     `json:"resource"`
	Context  PolicyDecideContext `json:"context"`
}

// PolicySubject names the user: either their access token (preferred — it is
// verified, and supplies scopes, amr and auth_time) or their user id.
type PolicySubject struct {
	Token  string `json:"token,omitempty"`
	UserID uint   `json:"user_id,omitempty"`
}

// PolicyDecideContext is the request context as the application observed it.
type PolicyDecideContext struct {
	// IP is the end user's address as the application saw it. Asserted by
	// the caller, like everything else it says about its own request.
	IP         string         `json:"ip,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// PolicyDecideResponse is the decision plus the mode it was made under. The
// mode is how an application's enforcement point knows whether to act on it:
// off — ignore; shadow — log a denial, allow; enforce — honour it.
type PolicyDecideResponse struct {
	policy.Decision
	Mode string `json:"mode"`
}
