package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// isRevoked reports whether the token's JTI has been individually revoked via
// /oauth/revoke (the JTI is blacklisted in used_tokens). Nil repo or an empty
// JTI means "not revoked"; a repo error fails open (returns false) so a
// transient store outage never locks out otherwise-valid tokens — consistent
// with Introspect's best-effort blacklist check. EPIC-14 / RFC-012: this is
// what propagates a per-token revocation to the direct-auth hot path, not just
// to introspection.
func isRevoked(ctx context.Context, usedTokenRepo repository.UsedTokenRepository, jti string) bool {
	if usedTokenRepo == nil || jti == "" {
		return false
	}
	revoked, err := usedTokenRepo.IsUsed(ctx, jti)
	return err == nil && revoked
}

// AuthMiddleware validates JWT tokens, verifies token version + revocation, and adds user info to context
func AuthMiddleware(tokenService *auth.TokenService, userRepo repository.UserRepository, usedTokenRepo repository.UsedTokenRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeAuthError(w, "authorization header required", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				writeAuthError(w, "invalid authorization header format", http.StatusUnauthorized)
				return
			}

			claims, err := tokenService.VerifyAccessToken(tokenString)
			if err != nil {
				writeAuthError(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}

			userID, err := strconv.ParseUint(claims.Subject, 10, 64)
			if err != nil {
				writeAuthError(w, "invalid token claims", http.StatusUnauthorized)
				return
			}

			user, err := userRepo.FindByID(r.Context(), uint(userID))
			if err != nil {
				writeAuthError(w, "user not found", http.StatusUnauthorized)
				return
			}

			// CRITICAL: Verify token version to support token revocation
			// If the user's token version has been incremented (via logout, password reset, etc.),
			// all previously issued tokens become invalid.
			//
			// FIND-01 fix: the previous guard `claims.TokenVersion > 0 &&` created a
			// bypass for tokens minted when TokenVersion was 0 (every new user before
			// their first nuclear revocation event).  After IncrementTokenVersion bumps
			// the DB row to 1, old tokens with TokenVersion=0 passed the "> 0" guard
			// as false and the check was silently skipped — the attacker remained
			// authenticated despite the revocation.
			//
			// The correct comparison is user.TokenVersion > claims.TokenVersion, which
			// matches the Introspect implementation (NEW-03 fix) and correctly catches
			// the 0→1, 1→2, and any N→N+k transitions.
			if user.TokenVersion > claims.TokenVersion {
				writeAuthError(w, "token has been revoked", http.StatusUnauthorized)
				return
			}

			// EPIC-14: reject a token whose JTI was individually revoked via
			// /oauth/revoke, so per-token revocation propagates to this hot path
			// (previously only Introspect honored the blacklist).
			if isRevoked(r.Context(), usedTokenRepo, claims.ID) {
				writeAuthError(w, "token has been revoked", http.StatusUnauthorized)
				return
			}

			// Check if user account is locked
			if user.IsLocked() {
				writeAuthError(w, "account is locked", http.StatusForbidden)
				return
			}

			// Add user info to context
			ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, user.ID)
			ctx = context.WithValue(ctx, contextkeys.UserRoleKey, string(user.Role))
			ctx = context.WithValue(ctx, contextkeys.CurrentUserKey, user)
			ctx = context.WithValue(ctx, contextkeys.JWTClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuthMiddleware extracts user info if token present, but doesn't require it
func OptionalAuthMiddleware(tokenService *auth.TokenService, userRepo repository.UserRepository, usedTokenRepo repository.UsedTokenRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				next.ServeHTTP(w, r)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				next.ServeHTTP(w, r)
				return
			}

			claims, err := tokenService.VerifyAccessToken(tokenString)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			userID, err := strconv.ParseUint(claims.Subject, 10, 64)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			user, err := userRepo.FindByID(r.Context(), uint(userID))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Verify token version — silently treat the request as unauthenticated
			// when the token has been revoked via nuclear revocation.
			//
			// FIND-01 fix: same correction as AuthMiddleware above.  The "> 0"
			// guard on claims.TokenVersion meant tokens minted when TokenVersion
			// was 0 were never rejected here, defeating nuclear revocation on the
			// OptionalAuth paths (e.g. POST /oauth/revoke Path 1 classification).
			if user.TokenVersion > claims.TokenVersion {
				next.ServeHTTP(w, r)
				return
			}

			// EPIC-14: a per-token-revoked token is treated as unauthenticated.
			if isRevoked(r.Context(), usedTokenRepo, claims.ID) {
				next.ServeHTTP(w, r)
				return
			}

			// Skip if user is locked
			if user.IsLocked() {
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, user.ID)
			ctx = context.WithValue(ctx, contextkeys.UserRoleKey, string(user.Role))
			ctx = context.WithValue(ctx, contextkeys.CurrentUserKey, user)
			ctx = context.WithValue(ctx, contextkeys.JWTClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserIDFromContext extracts the user ID from the request context
func GetUserIDFromContext(ctx context.Context) (uint, bool) {
	userID, ok := ctx.Value(contextkeys.UserIDKey).(uint)
	return userID, ok
}

// GetUserRoleFromContext extracts the user role from the request context
func GetUserRoleFromContext(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(contextkeys.UserRoleKey).(string)
	return role, ok
}

// writeAuthError writes a JSON error response for authentication failures.
//
// M-05 fix: the previous implementation used raw string concatenation
// (`{"error": "` + message + `"}`), which produces malformed JSON when
// message contains a double-quote or backslash.  json.NewEncoder escapes
// all special characters automatically.
func writeAuthError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="oauth2", error="invalid_token"`)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: message})
}
