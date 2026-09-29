package middleware

import (
	"net/http"
	"time"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// RequireFreshAuth gates the most destructive admin operations on a recent
// authentication ("step-up" / elevated scope). It requires the caller's access
// token to carry an auth_time (RFC 9068 / OIDC) no older than maxAge; otherwise
// it returns 403 with the machine-readable code "elevation_required" so the
// client can route the user through a fresh re-authentication (POST
// /api/admin/elevate) before retrying.
//
// It must run AFTER AuthMiddleware (which stashes the parsed access-token claims
// in JWTClaimsKey). A maxAge <= 0 disables the gate (pass-through). Because
// refresh propagates the original auth_time rather than updating it, a merely
// refreshed session is correctly treated as not fresh.
func RequireFreshAuth(maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxAge <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			claims, ok := r.Context().Value(contextkeys.JWTClaimsKey).(*auth.AccessTokenClaims)
			if !ok || claims == nil || claims.AuthTime == 0 {
				// No usable auth_time (e.g. a token minted without an interactive
				// authentication, or a refreshed token that lost freshness) cannot
				// prove recency — require elevation.
				http.Error(w, `{"error": "elevation_required"}`, http.StatusForbidden)
				return
			}
			if time.Since(time.Unix(claims.AuthTime, 0)) > maxAge {
				http.Error(w, `{"error": "elevation_required"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
