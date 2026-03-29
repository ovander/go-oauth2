package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// ServiceAccountMiddleware authenticates machine-to-machine requests carrying a
// client_credentials access token (sub = "app:{id}").
//
// It enforces two things:
//  1. The token is a valid, unexpired service account token (sub prefix "app:").
//  2. The app ID encoded in the token matches the {app_id} URL parameter —
//     a token issued for app 3 cannot touch app 7's resources.
//
// On success the resolved *model.App is stored in context under ServiceAccountAppKey.
func ServiceAccountMiddleware(appRepo repository.AppRepository, tokenService *auth.TokenService) func(http.Handler) http.Handler {
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

			// Service account tokens carry sub = "app:{numeric_id}"
			if !strings.HasPrefix(claims.Subject, "app:") {
				writeAuthError(w, "service account token required", http.StatusForbidden)
				return
			}

			appIDStr := strings.TrimPrefix(claims.Subject, "app:")
			appIDFromToken, err := strconv.ParseUint(appIDStr, 10, 64)
			if err != nil {
				writeAuthError(w, "invalid token claims", http.StatusUnauthorized)
				return
			}

			// Enforce: token must belong to the same app as the route's {app_id}
			routeAppID, err := strconv.ParseUint(chi.URLParam(r, "app_id"), 10, 64)
			if err != nil {
				writeAuthError(w, "invalid app ID in URL", http.StatusBadRequest)
				return
			}

			if appIDFromToken != routeAppID {
				writeAuthError(w, "token is not authorized for this app", http.StatusForbidden)
				return
			}

			// Load and validate the app
			app, err := appRepo.FindByID(r.Context(), uint(appIDFromToken))
			if err != nil {
				writeAuthError(w, "app not found", http.StatusUnauthorized)
				return
			}
			if !app.Active {
				writeAuthError(w, "app is inactive", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), contextkeys.ServiceAccountAppKey, app)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetServiceAccountAppFromContext returns the authenticated service account app,
// present only on routes protected by ServiceAccountMiddleware.
func GetServiceAccountAppFromContext(ctx context.Context) (*model.App, bool) {
	app, ok := ctx.Value(contextkeys.ServiceAccountAppKey).(*model.App)
	return app, ok
}
