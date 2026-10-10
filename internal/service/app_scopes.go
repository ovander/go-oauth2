package service

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ovander/go-oauth2/internal/model"
)

// Application-defined scopes (#336, on top of the A1 / P3-8 allowed_scopes
// policy).
//
// A resource server can define its own scope, for example "swingdrift:worker",
// and an operator registers it in the allowed_scopes of the clients that may
// obtain it. Such a scope is valid only for a client that lists it; for every
// other client it stays invalid_scope, whatever SCOPE_POLICY_MODE says.
//
// Grammar: "<namespace>:<name>", where
//
//	namespace = [a-z][a-z0-9-]{0,31}     (1 to 32 characters)
//	name      = [a-z][a-z0-9._-]{0,63}   (1 to 64 characters)
//
// so the whole scope is at most 97 characters, lower-case ASCII, with exactly
// one colon. Every character is in the RFC 6749 §3.3 scope-token set (NQCHAR),
// and none of them needs escaping in HTML, JSON or a space-separated claim.
//
// Reserved namespaces can never be used by an application: the first segment
// of every global scope (today openid, email, profile, offline_access, api,
// admin and monitoring, derived from validScopes so a future global "foo:bar"
// reserves "foo") plus socrate, oidc, oauth and oauth2.

// appScopePattern is the application-defined scope grammar.
var appScopePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}:[a-z][a-z0-9._-]{0,63}$`)

// fixedReservedScopeNamespaces are reserved whether or not a global scope uses
// them today.
var fixedReservedScopeNamespaces = []string{"socrate", "admin", "openid", "oidc", "oauth", "oauth2"}

// reservedScopeNamespaces is fixedReservedScopeNamespaces plus the first
// segment of every global scope.
var reservedScopeNamespaces = buildReservedScopeNamespaces()

func buildReservedScopeNamespaces() map[string]bool {
	reserved := make(map[string]bool, len(fixedReservedScopeNamespaces)+len(validScopes))
	for _, ns := range fixedReservedScopeNamespaces {
		reserved[ns] = true
	}
	for g := range validScopes {
		ns, _, _ := strings.Cut(g, ":")
		reserved[ns] = true
	}
	return reserved
}

// isAppScope reports whether s is a well-formed application-defined scope in a
// namespace that is not reserved. A global scope is never an app scope.
func isAppScope(s string) bool {
	if validScopes[s] || !appScopePattern.MatchString(s) {
		return false
	}
	ns, _, _ := strings.Cut(s, ":")
	return !reservedScopeNamespaces[ns]
}

// scopeValidForClient reports whether a requested scope token is valid for app:
// a global scope (the per-client policy is applied separately by
// enforceClientScopes), or an application-defined scope that app registers in
// its allowed_scopes. A nil app accepts global scopes only.
func scopeValidForClient(app *model.App, s string) bool {
	if validScopes[s] {
		return true
	}
	return app != nil && isAppScope(s) && app.RegistersScope(s)
}

// validateRequestedScope checks a space-separated requested scope for app. An
// empty scope is valid (the grant applies its default). The error does not say
// whether another client registers the scope.
func validateRequestedScope(app *model.App, scope string) error {
	if scope == "" {
		return nil
	}
	for _, s := range strings.Split(scope, " ") {
		if !scopeValidForClient(app, s) {
			return fmt.Errorf("%w: unknown scope '%s'", ErrInvalidScope, s)
		}
	}
	return nil
}

// checkRegisteredAppScopes re-checks a scope carried over from an earlier grant
// (an authorization code, a refresh token, a token-exchange subject token):
// every namespaced scope that is not global must still be an application-defined
// scope registered by app, so removing it from allowed_scopes stops it being
// renewed or exchanged. Other scope tokens are left to the existing rules,
// which keeps tokens issued before #336 behaving as they did.
func checkRegisteredAppScopes(app *model.App, scope string) error {
	for _, s := range strings.Fields(scope) {
		if validScopes[s] || !strings.Contains(s, ":") {
			continue
		}
		if app == nil || !isAppScope(s) || !app.RegistersScope(s) {
			return fmt.Errorf("%w: unknown scope '%s'", ErrInvalidScope, s)
		}
	}
	return nil
}
