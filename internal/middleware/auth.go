package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// AuthMiddleware validates JWT tokens, verifies token version, and adds user info to context
func AuthMiddleware(tokenService *auth.TokenService, userRepo repository.UserRepository) func(http.Handler) http.Handler {
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
			// all previously issued tokens become invalid
			if claims.TokenVersion > 0 && user.TokenVersion != claims.TokenVersion {
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
func OptionalAuthMiddleware(tokenService *auth.TokenService, userRepo repository.UserRepository) func(http.Handler) http.Handler {
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

			// Verify token version - silently skip if token is revoked
			if claims.TokenVersion > 0 && user.TokenVersion != claims.TokenVersion {
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

// writeAuthError writes a JSON error response for authentication failures
func writeAuthError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="oauth2", error="invalid_token"`)
	w.WriteHeader(statusCode)
	w.Write([]byte(`{"error": "` + message + `"}`))
}
