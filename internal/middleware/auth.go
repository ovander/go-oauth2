package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/socrate-auth/go-oauth/internal/contextkeys"
	"github.com/socrate-auth/go-oauth/internal/repository"
	"github.com/socrate-auth/go-oauth/internal/shared/auth"
)

// AuthMiddleware validates JWT tokens and adds user info to context
func AuthMiddleware(tokenService *auth.TokenService, userRepo repository.UserRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error": "authorization header required"}`, http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				http.Error(w, `{"error": "invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			claims, err := tokenService.VerifyAccessToken(tokenString)
			if err != nil {
				http.Error(w, `{"error": "invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			userID, err := strconv.ParseUint(claims.Subject, 10, 64)
			if err != nil {
				http.Error(w, `{"error": "invalid token claims"}`, http.StatusUnauthorized)
				return
			}

			user, err := userRepo.FindByID(r.Context(), uint(userID))
			if err != nil {
				http.Error(w, `{"error": "user not found"}`, http.StatusUnauthorized)
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
