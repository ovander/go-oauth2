package service

import (
	"fmt"

	"github.com/ovander/go-oauth2/internal/model"
)

// Admin app sign-in policy modes (ADMIN_APP_SIGNIN_POLICY). A Socrate admin or
// superadmin is an operator account: it has no membership in any application
// and, historically, is treated as the admin of any app it signs in to.
// "off" (default) keeps that; "observe" keeps it but audits every sign-in of
// an admin to an application that is not an operator console; "enforce"
// refuses it, so an operator account only ever gets tokens for the consoles.
const (
	AdminAppSignInOff     = "off"
	AdminAppSignInObserve = "observe"
	AdminAppSignInEnforce = "enforce"
)

// ErrAdminAppSignInRefused is returned when ADMIN_APP_SIGNIN_POLICY=enforce
// refuses a Socrate admin on an application that is not an operator console.
// It wraps ErrRoleNotFound, so every caller that handles "no access to this
// app" (the refresh grant's invalid_grant included) handles it the same way.
var ErrAdminAppSignInRefused = fmt.Errorf("%w: Socrate administrator accounts may sign in to the operator consoles only", ErrRoleNotFound)

// AdminAppSignInPolicy decides whether a Socrate admin may obtain tokens for an
// application it is not a member of. The zero value is "off".
type AdminAppSignInPolicy struct {
	mode     string
	consoles map[string]struct{}
}

// NewAdminAppSignInPolicy builds the policy from its mode and the client_ids of
// the operator consoles, where an admin keeps signing in under every mode.
// Empty client_ids are ignored; an unknown mode is "off".
func NewAdminAppSignInPolicy(mode string, consoleClientIDs []string) AdminAppSignInPolicy {
	p := AdminAppSignInPolicy{mode: AdminAppSignInOff, consoles: map[string]struct{}{}}
	if mode == AdminAppSignInObserve || mode == AdminAppSignInEnforce {
		p.mode = mode
	}
	for _, id := range consoleClientIDs {
		if id != "" {
			p.consoles[id] = struct{}{}
		}
	}
	return p
}

// Mode reports the policy mode ("off", "observe" or "enforce").
func (p AdminAppSignInPolicy) Mode() string {
	if p.mode == "" {
		return AdminAppSignInOff
	}
	return p.mode
}

// outsideConsoles reports whether user is a Socrate admin signing in to app,
// an application that is not an operator console, while the policy is on.
// Such a sign-in is audited (observe) or refused (enforce).
func (p AdminAppSignInPolicy) outsideConsoles(user *model.User, app *model.App) bool {
	if p.Mode() == AdminAppSignInOff || user == nil || app == nil || !user.IsGlobalAdmin() {
		return false
	}
	_, console := p.consoles[app.ClientID]
	return !console
}

// refuses reports whether the policy refuses the sign-in (enforce mode).
func (p AdminAppSignInPolicy) refuses() bool { return p.Mode() == AdminAppSignInEnforce }

// adminAppSignInDetails is the audit payload of an admin_app_signin event.
func (p AdminAppSignInPolicy) adminAppSignInDetails(user *model.User, app *model.App, path string) map[string]interface{} {
	return map[string]interface{}{
		"email":     user.Email,
		"role":      string(user.Role),
		"client_id": app.ClientID,
		"path":      path,
		"policy":    p.Mode(),
	}
}
