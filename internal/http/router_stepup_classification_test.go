package http

import (
	"slices"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/policy"
)

// adminWritesWithoutStepUp are the state-changing admin routes that do not
// require fresh authentication, each with the reason. Every other
// state-changing admin route must be in policy.StepUpActions.
var adminWritesWithoutStepUp = map[string]string{
	"POST /api/admin/alerts/{id}/acknowledge": "operational acknowledgement; changes no access",
	"POST /api/admin/reports/security":        "generates a report",
	"POST /api/admin/users/{id}/unlock":       "restores a user's access; operational",
	"PUT /api/admin/superadmins/{id}":         "step-up added with #353",
	"PUT /api/admin/users/{id}/attributes":    "protected by #352",
}

// Every state-changing admin route is either a step-up action or listed above
// with a reason, so a new write route cannot skip step-up by accident: this
// test fails until it is classified.
func TestAdminWriteRoutes_AreClassifiedForStepUp(t *testing.T) {
	var writes []string
	for _, a := range a4Actions(t) {
		if !strings.HasPrefix(a, "GET ") {
			writes = append(writes, a)
		}
	}
	for _, w := range writes {
		_, exempt := adminWritesWithoutStepUp[w]
		stepUp := slices.Contains(policy.StepUpActions, w)
		switch {
		case stepUp && exempt:
			t.Errorf("%s is both a step-up action and listed without step-up", w)
		case !stepUp && !exempt:
			t.Errorf("%s changes state but is neither in policy.StepUpActions nor in adminWritesWithoutStepUp", w)
		}
	}
	for w := range adminWritesWithoutStepUp {
		if !slices.Contains(writes, w) {
			t.Errorf("adminWritesWithoutStepUp lists %s, which is not a state-changing admin route", w)
		}
	}
}
