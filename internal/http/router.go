package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/ovandermoten/go-oauth2/internal/handler"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

type RouterConfig struct {
	AllowedOrigins    []string
	LoginRateLimiter  *middleware.RateLimiter
	SignupRateLimiter *middleware.RateLimiter
}

// Routers holds both the OAuth and Admin routers for separate port binding
type Routers struct {
	OAuth http.Handler // Public-facing OAuth/OIDC server (port 8080)
	Admin http.Handler // Internal admin API (port 8081)
}

// NewRouters creates separate routers for OAuth server and Admin API
// This allows running them on different ports with different firewall rules
func NewRouters(
	authHandler *handler.AuthHandler,
	oauthHandler *handler.OAuthHandler,
	appUsersHandler *handler.AppUsersHandler,
	profileHandler *handler.ProfileHandler,
	adminHandler *handler.AdminHandler,
	adminAuthHandler *handler.AdminAuthHandler,
	dashboardHandler *handler.DashboardHandler,
	healthHandler *handler.HealthHandler,
	appLogsHandler *handler.AppLogsHandler,
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	config RouterConfig,
) *Routers {
	return &Routers{
		OAuth: newOAuthRouter(authHandler, oauthHandler, profileHandler, healthHandler, tokenService, userRepo, config),
		Admin: newAdminRouter(adminHandler, adminAuthHandler, dashboardHandler, appUsersHandler, appLogsHandler, healthHandler, tokenService, userRepo, userAppRoleRepo, config),
	}
}

// newOAuthRouter creates the public-facing OAuth/OIDC server router
// This should be exposed on the public port (e.g., 8080)
func newOAuthRouter(
	authHandler *handler.AuthHandler,
	oauthHandler *handler.OAuthHandler,
	profileHandler *handler.ProfileHandler,
	healthHandler *handler.HealthHandler,
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	config RouterConfig,
) http.Handler {
	r := chi.NewRouter()

	// Global Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(middleware.CorrelationID())
	r.Use(middleware.SecurityHeaders())

	// CORS for public OAuth endpoints
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   config.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Correlation-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(middleware.JSONContentType())

	// ==========================================
	// Health Routes
	// ==========================================
	r.Get("/health", healthHandler.Health)
	r.Get("/health/liveness", healthHandler.Liveness)
	r.Get("/health/readiness", healthHandler.Readiness)

	// ==========================================
	// OpenID Connect Discovery
	// ==========================================
	r.Get("/.well-known/openid-configuration", oauthHandler.OpenIDConfiguration)
	r.Get("/.well-known/jwks.json", oauthHandler.JWKS)

	// ==========================================
	// OAuth 2.0 Endpoints
	// ==========================================
	r.Route("/oauth", func(r chi.Router) {
		r.With(middleware.OptionalAuthMiddleware(tokenService, userRepo)).
			Get("/authorize", oauthHandler.Authorize)

		r.With(middleware.NoCacheHeaders()).
			Post("/token", oauthHandler.Token)

		r.With(middleware.AuthMiddleware(tokenService, userRepo)).
			Get("/userinfo", oauthHandler.UserInfo)
		r.With(middleware.AuthMiddleware(tokenService, userRepo)).
			Post("/userinfo", oauthHandler.UserInfo)

		r.Post("/introspect", oauthHandler.Introspect)

		r.With(middleware.OptionalAuthMiddleware(tokenService, userRepo)).
			Post("/revoke", oauthHandler.Revoke)

		r.With(middleware.OptionalAuthMiddleware(tokenService, userRepo)).
			Get("/logout", oauthHandler.EndSession)
		r.With(middleware.OptionalAuthMiddleware(tokenService, userRepo)).
			Post("/logout", oauthHandler.EndSession)
	})

	// ==========================================
	// User-Facing API Routes (Authentication & Profile)
	// ==========================================
	r.Route("/api", func(r chi.Router) {
		// UserInfo endpoint
		r.With(middleware.AuthMiddleware(tokenService, userRepo)).
			Get("/userinfo", authHandler.GetUserInfo)

		// Auth Routes (Public)
		r.Route("/auth", func(r chi.Router) {
			r.With(middleware.RateLimitMiddleware(config.SignupRateLimiter)).
				Post("/signup", authHandler.Signup)

			r.Get("/verify-email", authHandler.VerifyEmail)

			r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter)).
				Post("/login", authHandler.Login)

			r.Post("/refresh", authHandler.Refresh)

			r.With(middleware.AuthMiddleware(tokenService, userRepo)).
				Post("/logout", authHandler.Logout)

			r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter)).
				Post("/request-password-reset", authHandler.RequestPasswordReset)
			r.Post("/reset-password", authHandler.ResetPassword)

			r.Get("/invite", authHandler.ValidateInvite)
			r.Post("/invite", authHandler.AcceptInvite)
		})

		// Profile Routes (Protected - user self-service)
		r.Route("/profile", func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(tokenService, userRepo))
			r.Get("/", profileHandler.GetProfile)
			r.Put("/", profileHandler.UpdateProfile)
			r.Patch("/", profileHandler.UpdateProfile)
		})
	})

	return r
}

// newAdminRouter creates the internal admin API router
// This should be exposed on an internal port (e.g., 8081) behind a firewall
func newAdminRouter(
	adminHandler *handler.AdminHandler,
	adminAuthHandler *handler.AdminAuthHandler,
	dashboardHandler *handler.DashboardHandler,
	appUsersHandler *handler.AppUsersHandler,
	appLogsHandler *handler.AppLogsHandler,
	healthHandler *handler.HealthHandler,
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	config RouterConfig,
) http.Handler {
	r := chi.NewRouter()

	// Global Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(middleware.CorrelationID())
	r.Use(middleware.SecurityHeaders())

	// More restrictive CORS for admin API (internal use only)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   config.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Correlation-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(middleware.JSONContentType())

	// ==========================================
	// Health Routes (for internal monitoring)
	// ==========================================
	r.Get("/health", healthHandler.Health)
	r.Get("/health/liveness", healthHandler.Liveness)
	r.Get("/health/readiness", healthHandler.Readiness)

	// ==========================================
	// Admin Authentication (public - no auth required)
	// ==========================================
	r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter)).
		Post("/api/admin/login", adminAuthHandler.Login)

	// ==========================================
	// Admin API Routes (protected)
	// ==========================================
	r.Route("/api/admin", func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(tokenService, userRepo))

		// Current admin profile
		r.Get("/profile", adminAuthHandler.GetProfile)

		// Stats and activity
		r.Get("/stats", adminHandler.GetStats)
		r.Get("/activity", adminHandler.GetActivity)

		// App management (OAuth clients)
		r.Route("/apps", func(r chi.Router) {
			r.Get("/", adminHandler.ListApps)
			r.Post("/", adminHandler.CreateApp)

			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", adminHandler.GetApp)
				r.Put("/", adminHandler.UpdateApp)
				r.Delete("/", adminHandler.DeleteApp)
				r.Post("/rotate-secret", adminHandler.RotateSecret)
			})
		})

		// User management (global admin only)
		r.Route("/users", func(r chi.Router) {
			r.Get("/", adminHandler.ListUsers)

			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", adminHandler.GetUser)
				r.Post("/revoke-tokens", adminHandler.RevokeUserTokens)
				r.Post("/unlock", adminHandler.UnlockUser)
			})
		})

		// Dashboard endpoints
		r.Route("/dashboard", func(r chi.Router) {
			r.Get("/stats", dashboardHandler.GetStats)
			r.Get("/activity", dashboardHandler.GetActivity)
			r.Get("/health", dashboardHandler.GetHealth)
			r.Get("/login-trends", dashboardHandler.GetLoginTrends)
			r.Get("/app-usage", dashboardHandler.GetAppUsage)
		})

		// Superadmin management
		r.Route("/superadmins", func(r chi.Router) {
			r.Get("/", adminHandler.ListSuperadmins)
			r.Post("/", adminHandler.CreateSuperadmin)

			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", adminHandler.GetSuperadmin)
				r.Put("/", adminHandler.UpdateSuperadmin)
				r.Delete("/", adminHandler.DeleteSuperadmin)
			})
		})
	})

	// ==========================================
	// App-Scoped User Management (for app admins)
	// ==========================================
	r.Route("/api/apps/{app_id}", func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(tokenService, userRepo))
		r.Use(middleware.RequireAppAccess(userAppRoleRepo))

		r.Route("/users", func(r chi.Router) {
			r.Get("/", appUsersHandler.ListUsers)
			r.Post("/", appUsersHandler.CreateUser)

			r.Route("/{user_id}", func(r chi.Router) {
				r.Get("/", appUsersHandler.GetUser)
				r.Put("/", appUsersHandler.UpdateUserRole)
				r.Delete("/", appUsersHandler.RemoveUser)
				r.Post("/resend-verification", appUsersHandler.ResendVerification)
				r.Post("/reset-password", appUsersHandler.ForcePasswordReset)
			})
		})

		r.With(middleware.RequireAppAdmin(userAppRoleRepo)).
			Get("/logs", appLogsHandler.GetLogs)
	})

	return r
}

// NewRouter creates a combined router (for backwards compatibility or single-port mode)
// Use NewRouters() for production deployments with separate ports
func NewRouter(
	authHandler *handler.AuthHandler,
	oauthHandler *handler.OAuthHandler,
	appUsersHandler *handler.AppUsersHandler,
	profileHandler *handler.ProfileHandler,
	adminHandler *handler.AdminHandler,
	adminAuthHandler *handler.AdminAuthHandler,
	dashboardHandler *handler.DashboardHandler,
	healthHandler *handler.HealthHandler,
	appLogsHandler *handler.AppLogsHandler,
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	config RouterConfig,
) http.Handler {
	r := chi.NewRouter()

	// Global Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(middleware.CorrelationID())
	r.Use(middleware.SecurityHeaders())

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   config.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Correlation-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(middleware.JSONContentType())

	// Mount OAuth router
	oauthRouter := newOAuthRouter(authHandler, oauthHandler, profileHandler, healthHandler, tokenService, userRepo, config)
	r.Mount("/", oauthRouter)

	// Mount Admin router under /admin prefix (for single-port mode)
	adminRouter := newAdminRouter(adminHandler, adminAuthHandler, dashboardHandler, appUsersHandler, appLogsHandler, healthHandler, tokenService, userRepo, userAppRoleRepo, config)
	r.Mount("/manage", adminRouter)

	return r
}
