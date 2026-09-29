package middleware

import (
	"net/http"
	"strings"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// RequireScope gates a route on an OAuth scope present in the access token's
// `scope` claim (RFC 8693 / RFC 6750). The "admin" scope is a super-scope that
// satisfies any requirement, so the full-privilege admin console (which holds
// it) is never blocked, while a least-privilege client (e.g. the monitoring
// BFF, scoped to monitoring:read/write) is confined to its routes.
//
// When enforce is false the gate is a pass-through. Scope separation is thus
// opt-in via ADMIN_SCOPE_MODE=enforce, so enabling it is a deliberate step that
// requires clients to be registered with the right scopes first.
//
// Must run AFTER AuthMiddleware, which stores *auth.AccessTokenClaims under
// contextkeys.JWTClaimsKey.
func RequireScope(required string, enforce bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enforce {
				next.ServeHTTP(w, r)
				return
			}
			claims, ok := r.Context().Value(contextkeys.JWTClaimsKey).(*auth.AccessTokenClaims)
			if !ok || claims == nil || !scopeSatisfies(claims.Scope, required) {
				http.Error(w, `{"error": "insufficient_scope"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// scopeSatisfies reports whether a space-delimited granted scope string contains
// the required scope, treating "admin" as a wildcard super-scope.
func scopeSatisfies(granted, required string) bool {
	for _, s := range strings.Fields(granted) {
		if s == required || s == "admin" {
			return true
		}
	}
	return false
}
