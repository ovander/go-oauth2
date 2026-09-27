package policy

// AdminPrefix is the path prefix the admin enforcement point covers.
const AdminPrefix = "/api/admin"

// StepUpActions are the admin routes that the router wraps in
// RequireFreshAuth today. The baseline expresses the same requirement as an
// obligation; the router parity test fails if the two lists ever drift.
var StepUpActions = []string{
	"DELETE /api/admin/apps/{id}",
	"POST /api/admin/apps/{id}/rotate-secret",
	"POST /api/admin/users/{id}/revoke-tokens",
	"POST /api/admin/users/{id}/block",
	"POST /api/admin/webhooks",
	"POST /api/admin/webhooks/deliveries/{id}/requeue",
	"PUT /api/admin/webhooks/{id}",
	"DELETE /api/admin/webhooks/{id}",
	"POST /api/admin/webhooks/{id}/rotate-secret",
	"POST /api/admin/superadmins",
	"DELETE /api/admin/superadmins/{id}",
	"POST /api/admin/security/blocked-ips",
	"DELETE /api/admin/security/blocked-ips/{id}",
	"POST /api/admin/alerts/rules",
	"PUT /api/admin/alerts/rules/{id}",
	"DELETE /api/admin/alerts/rules/{id}",
}

// Baseline is the rule set seeded as version 1. It restates the admin API's
// existing code gates as rules, one for one:
//
//	RequireGlobalAdmin                 → global-admins
//	RequireRole("superadmin")          → superadmin-management
//	RequirePasswordChangeComplete      → password-change-pending
//	RequireFreshAuth (on StepUpActions) → destructive-step-up
//
// That is what makes shadow mode meaningful from the first request: the PDP
// and the code should agree everywhere, so every recorded divergence is either
// a bug in one of them or a rule an operator has since added on purpose.
//
// ADMIN_SCOPE_MODE's scope gates are deliberately not mirrored — they are
// switched by an environment variable a rule cannot see, so a baseline that
// mirrored them would be wrong in one of the two modes. docs/EXTENSIBILITY.md
// gives the rules to add when that mode is enforced.
func Baseline() []Rule {
	admins := []any{"admin", "superadmin"}
	return []Rule{
		{
			ID:          "global-admins",
			Description: "The admin API is for global admins (mirrors RequireGlobalAdmin).",
			Effect:      EffectAllow,
			Actions:     []string{"* " + AdminPrefix + "/*"},
			When:        &Condition{Attr: "principal.role", Op: opIn, Value: admins},
		},
		{
			ID:          "superadmin-management",
			Description: "Only a superadmin may manage superadmins (mirrors RequireRole(\"superadmin\")).",
			Effect:      EffectDeny,
			Actions: []string{
				"* " + AdminPrefix + "/superadmins",
				"* " + AdminPrefix + "/superadmins/*",
			},
			When: &Condition{Attr: "principal.role", Op: opNe, Value: "superadmin"},
		},
		{
			ID:          "password-change-pending",
			Description: "An admin with a forced password change pending is blocked until they change it (mirrors RequirePasswordChangeComplete).",
			Effect:      EffectDeny,
			Actions:     []string{"* " + AdminPrefix + "/*"},
			When:        &Condition{Attr: "principal.must_change_password", Op: opEq, Value: true},
		},
		{
			ID:          "destructive-step-up",
			Description: "Destructive admin operations need a fresh authentication (mirrors RequireFreshAuth).",
			Effect:      EffectAllow,
			Actions:     append([]string(nil), StepUpActions...),
			When:        &Condition{Attr: "principal.role", Op: opIn, Value: admins},
			Obligations: []string{ObligationFreshAuth},
		},
	}
}
