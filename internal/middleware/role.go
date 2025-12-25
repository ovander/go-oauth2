package middleware

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
)

// RequireRole checks if the user has one of the specified roles
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	roleSet := make(map[string]bool)
	for _, r := range roles {
		roleSet[r] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value(contextkeys.UserRoleKey).(string)
			if !ok {
				http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if !roleSet[userRole] {
				http.Error(w, `{"error": "forbidden"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireGlobalAdmin checks if the user has admin or superadmin global role
func RequireGlobalAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
			if !ok {
				http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if !user.IsGlobalAdmin() {
				http.Error(w, `{"error": "forbidden"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAppAdmin checks if the user has admin role for the specified app
func RequireAppAdmin(userAppRoleRepo repository.UserAppRoleRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(contextkeys.UserIDKey).(uint)
			if !ok {
				http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
				return
			}

			appIDStr := chi.URLParam(r, "app_id")
			appID, err := strconv.ParseUint(appIDStr, 10, 64)
			if err != nil {
				http.Error(w, `{"error": "invalid app ID"}`, http.StatusBadRequest)
				return
			}

			userAppRole, err := userAppRoleRepo.FindByUserAndApp(r.Context(), userID, uint(appID))
			if err != nil {
				http.Error(w, `{"error": "forbidden"}`, http.StatusForbidden)
				return
			}

			if userAppRole.Role != model.AppRoleAdmin {
				// Check if user is global admin
				user, ok := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
				if !ok || !user.IsGlobalAdmin() {
					http.Error(w, `{"error": "forbidden"}`, http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAppAccess checks if the user has any role for the specified app
func RequireAppAccess(userAppRoleRepo repository.UserAppRoleRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(contextkeys.UserIDKey).(uint)
			if !ok {
				http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
				return
			}

			appIDStr := chi.URLParam(r, "app_id")
			appID, err := strconv.ParseUint(appIDStr, 10, 64)
			if err != nil {
				http.Error(w, `{"error": "invalid app ID"}`, http.StatusBadRequest)
				return
			}

			_, err = userAppRoleRepo.FindByUserAndApp(r.Context(), userID, uint(appID))
			if err != nil {
				// Check if user is global admin
				user, ok := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
				if !ok || !user.IsGlobalAdmin() {
					http.Error(w, `{"error": "forbidden"}`, http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
