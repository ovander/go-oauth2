package http

import (
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/ovandermoten/go-oauth2/internal/handler"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/dpop"
	internalweb "github.com/ovandermoten/go-oauth2/internal/web"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"github.com/ovandermoten/go-oauth2/web"
)

// corsHandler builds a chi/cors handler from the RouterConfig.
//
// H-06 fix: go-chi/cors reflects any Origin back when AllowedOrigins is ["*"]
// and AllowCredentials is true, effectively allowing cross-origin credentialed
// requests from any domain.  The CORS spec forbids combining a wildcard with
// credentials, so we enforce AllowCredentials: false whenever the origin list
// contains only the wildcard.  Callers that need credentialed cross-origin
// requests must supply an explicit origin list via ALLOWED_ORIGINS.
func corsHandler(config RouterConfig) func(http.Handler) http.Handler {
	allowCredentials := len(config.AllowedOrigins) > 0
	for _, o := range config.AllowedOrigins {
		if o == "*" {
			allowCredentials = false
			break
		}
	}
	origins := config.AllowedOrigins
	if len(origins) == 0 {
		origins = []string{"*"}
	}
	return cors.Handler(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Correlation-ID"},
		ExposedHeaders:   []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Correlation-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"},
		AllowCredentials: allowCredentials,
		MaxAge:           300,
	})
}

type RouterConfig struct {
	AllowedOrigins    []string
	LoginRateLimiter  *middleware.RateLimiter
	SignupRateLimiter *middleware.RateLimiter
	// MED-05: TokenRateLimiter throttles POST /oauth/token to prevent
	// authorization-code brute-force, refresh-token scanning, and client
	// credential password-spraying.  Keyed by client IP.  Nil disables.
	TokenRateLimiter *middleware.RateLimiter
	IPBlockChecker   *middleware.IPBlockChecker // Optional: nil disables IP blocking
	// TrustedProxyCIDRs lists upstream proxies whose X-Forwarded-For / X-Real-IP
	// headers are trusted for real-IP extraction.  Leave nil to always use
	// RemoteAddr (safe when the server is exposed directly to the internet).
	TrustedProxyCIDRs []*net.IPNet
	// DPoP (RFC 9449) observe-mode telemetry on the token endpoint. DPoPMode is
	// "off" (disabled), "observe", or "enforce"; DPoPReplayCache backs proof
	// replay detection; DPoPHTUBase is the canonical scheme://host of the issuer.
	// All zero/nil values leave the token endpoint unchanged.
	DPoPMode        string
	DPoPReplayCache dpop.ReplayCache
	DPoPHTUBase     string
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
	mfaHandler *handler.MFAHandler,
	adminHandler *handler.AdminHandler,
	adminAuthHandler *handler.AdminAuthHandler,
	dashboardHandler *handler.DashboardHandler,
	healthHandler *handler.HealthHandler,
	appLogsHandler *handler.AppLogsHandler,
	monitoringHandler *handler.MonitoringHandler,
	adminLogsHandler *handler.AdminLogsHandler,
	settingsHandler *handler.SettingsHandler,
	webHandler *internalweb.WebHandler,
	magicLinkHandler *handler.MagicLinkHandler,
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	appRepo repository.AppRepository,
	config RouterConfig,
) *Routers {
	return &Routers{
		OAuth: newOAuthRouter(authHandler, oauthHandler, webHandler, profileHandler, mfaHandler, healthHandler, magicLinkHandler, tokenService, userRepo, config),
		Admin: newAdminRouter(adminHandler, adminAuthHandler, dashboardHandler, appUsersHandler, appLogsHandler, monitoringHandler, adminLogsHandler, settingsHandler, healthHandler, magicLinkHandler, tokenService, userRepo, userAppRoleRepo, appRepo, config),
	}
}

// newOAuthRouter creates the public-facing OAuth/OIDC server router
// This should be exposed on the public port (e.g., 8080)
func newOAuthRouter(
	authHandler *handler.AuthHandler,
	oauthHandler *handler.OAuthHandler,
	webHandler *internalweb.WebHandler,
	profileHandler *handler.ProfileHandler,
	mfaHandler *handler.MFAHandler, // nil-safe; MFA self-service routes
	healthHandler *handler.HealthHandler,
	magicLinkHandler *handler.MagicLinkHandler, // nil-safe; only Verify is registered here
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	config RouterConfig,
) http.Handler {
	r := chi.NewRouter()

	// Global Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	// CorrelationID must run before the request logger so the correlation ID
	// is present in the context the logger reads (RFC-008).
	r.Use(middleware.CorrelationID())
	r.Use(logger.RequestLoggerMiddleware)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.AppVersion)

	// IP Blocking middleware (automatic defense)
	if config.IPBlockChecker != nil {
		r.Use(middleware.IPBlockMiddleware(config.IPBlockChecker, config.TrustedProxyCIDRs))
	}

	// CORS for public OAuth endpoints (H-06: wildcard + credentials disallowed)
	r.Use(corsHandler(config))

	// ==========================================
	// Static Files (CSS, JS for login pages)
	// ==========================================
	r.Handle("/static/*", http.StripPrefix("/static/", web.StaticFileServer()))

	// ==========================================
	// Health Routes (JSON)
	// ==========================================
	r.With(middleware.JSONContentType()).Get("/health", healthHandler.Health)
	r.With(middleware.JSONContentType()).Get("/health/liveness", healthHandler.Liveness)
	r.With(middleware.JSONContentType()).Get("/health/readiness", healthHandler.Readiness)
	r.With(middleware.JSONContentType()).Get("/version", healthHandler.Version)

	// ==========================================
	// OpenID Connect Discovery (JSON)
	// ==========================================
	r.With(middleware.JSONContentType()).Get("/.well-known/openid-configuration", oauthHandler.OpenIDConfiguration)
	r.With(middleware.JSONContentType()).Get("/.well-known/jwks.json", oauthHandler.JWKS)

	// ==========================================
	// OAuth 2.0 Endpoints
	// ==========================================
	r.Route("/oauth", func(r chi.Router) {
		// Authorization endpoint - returns HTML login page or redirects
		r.With(middleware.OptionalAuthMiddleware(tokenService, userRepo)).
			Get("/authorize", oauthHandler.Authorize)
		// H-07 fix: POST /authorize processes credentials; rate-limit it the same
		// way as the direct login endpoint to prevent credential-stuffing attacks.
		r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter, config.TrustedProxyCIDRs)).
			Post("/authorize", oauthHandler.AuthorizePost)

		// Token endpoint - JSON
		// MED-05: apply per-IP rate limiting to prevent brute-force attacks
		// against authorization codes, refresh tokens, and client credentials.
		dpopMW := middleware.DPoP(config.DPoPReplayCache, config.DPoPMode, config.DPoPHTUBase)
		if config.TokenRateLimiter != nil {
			r.With(middleware.JSONContentType(), middleware.NoCacheHeaders(),
				middleware.RateLimitMiddleware(config.TokenRateLimiter, config.TrustedProxyCIDRs), dpopMW).
				Post("/token", oauthHandler.Token)
		} else {
			r.With(middleware.JSONContentType(), middleware.NoCacheHeaders(), dpopMW).
				Post("/token", oauthHandler.Token)
		}

		r.With(middleware.JSONContentType(), middleware.AuthMiddleware(tokenService, userRepo)).
			Get("/userinfo", oauthHandler.UserInfo)
		r.With(middleware.JSONContentType(), middleware.AuthMiddleware(tokenService, userRepo)).
			Post("/userinfo", oauthHandler.UserInfo)

		r.With(middleware.JSONContentType()).Post("/introspect", oauthHandler.Introspect)

		r.With(middleware.JSONContentType(), middleware.OptionalAuthMiddleware(tokenService, userRepo)).
			Post("/revoke", oauthHandler.Revoke)

		r.With(middleware.OptionalAuthMiddleware(tokenService, userRepo)).
			Get("/logout", oauthHandler.EndSession)
		r.With(middleware.OptionalAuthMiddleware(tokenService, userRepo)).
			Post("/logout", oauthHandler.EndSession)
	})

	// ==========================================
	// Server-Rendered Auth Pages (HTML)
	// ==========================================
	r.Route("/auth", func(r chi.Router) {
		// Login flow
		r.Get("/login", webHandler.LoginPage)
		r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter, config.TrustedProxyCIDRs)).
			Post("/login", webHandler.LoginSubmit)

		// Signup flow
		r.Get("/signup", webHandler.SignupPage)
		r.With(middleware.RateLimitMiddleware(config.SignupRateLimiter, config.TrustedProxyCIDRs)).
			Post("/signup", webHandler.SignupSubmit)

		// Password reset flow
		// LOW-06 fix: rate-limit password reset and invite submission to
		// prevent email flooding / mailbombing.  The forgot-password form
		// triggers email sending; an attacker who submits it rapidly can
		// flood a victim's inbox.  We re-use the login rate limiter (same
		// IP-keyed window) since this is a low-frequency legitimate action.
		r.Get("/forgot-password", webHandler.ForgotPasswordPage)
		r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter, config.TrustedProxyCIDRs)).
			Post("/forgot-password", webHandler.ForgotPasswordSubmit)
		r.Get("/reset-password", webHandler.ResetPasswordPage)
		r.Post("/reset-password", webHandler.ResetPasswordSubmit)

		// Email verification
		r.Get("/verify-email", webHandler.VerifyEmailPage)

		// Invitation acceptance
		r.Get("/invite", webHandler.AcceptInvitePage)
		r.Post("/invite", webHandler.AcceptInviteSubmit)
	})

	// ==========================================
	// User-Facing API Routes (Authentication & Profile)
	// ==========================================
	r.Route("/api", func(r chi.Router) {
		r.Use(middleware.JSONContentType())

		// UserInfo endpoint
		r.With(middleware.AuthMiddleware(tokenService, userRepo)).
			Get("/userinfo", authHandler.GetUserInfo)

		// Auth Routes (Public)
		r.Route("/auth", func(r chi.Router) {
			r.With(middleware.RateLimitMiddleware(config.SignupRateLimiter, config.TrustedProxyCIDRs)).
				Post("/signup", authHandler.Signup)

			r.Get("/verify-email", authHandler.VerifyEmail)

			r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter, config.TrustedProxyCIDRs)).
				Post("/login", authHandler.Login)

			// FIND-02 fix: apply the same per-IP token rate limiter to the direct
			// API refresh endpoint as is applied to POST /oauth/token (MED-05).
			// Without this, an attacker could bypass the token endpoint limiter by
			// sending refresh token probes directly to /api/auth/refresh at
			// unlimited speed, defeating the brute-force protection added in MED-05.
			// Using the same config.TokenRateLimiter instance also means the two
			// endpoints share a single per-IP counter — exhausting one exhausts both.
			if config.TokenRateLimiter != nil {
				r.With(middleware.RateLimitMiddleware(config.TokenRateLimiter, config.TrustedProxyCIDRs)).
					Post("/refresh", authHandler.Refresh)
			} else {
				r.Post("/refresh", authHandler.Refresh)
			}

			r.With(middleware.AuthMiddleware(tokenService, userRepo)).
				Post("/logout", authHandler.Logout)

			// LOW-06 fix: request-password-reset triggers email sending; rate-limit
			// it to prevent mailbombing.  reset-password does not send email but
			// is rate-limited to slow brute-force attempts on the reset token.
			r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter, config.TrustedProxyCIDRs)).
				Post("/request-password-reset", authHandler.RequestPasswordReset)
			r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter, config.TrustedProxyCIDRs)).
				Post("/reset-password", authHandler.ResetPassword)

			r.Get("/invite", authHandler.ValidateInvite)
			r.Post("/invite", authHandler.AcceptInvite)

			// Magic-link verify (passwordless) — public endpoint.
			// POST /api/auth/magic-link/verify — exchange a single-use token for
			// a full token set (access + refresh + ID).
			//
			// The REQUEST side lives on the admin router under
			// /api/apps/{app_id}/service/magic-link (M2M / service-account only).
			// Verify is POST-only: email-scanners follow GET links and would silently
			// consume the single-use token before the user clicks.
			if magicLinkHandler != nil {
				r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter, config.TrustedProxyCIDRs)).
					Post("/magic-link/verify", magicLinkHandler.Verify)
			}
		})

		// Profile Routes (Protected - user self-service)
		r.Route("/profile", func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(tokenService, userRepo))
			r.Get("/", profileHandler.GetProfile)
			r.Put("/", profileHandler.UpdateProfile)
			r.Patch("/", profileHandler.UpdateProfile)

			// MFA self-service (TOTP) — RFC-011 / EPIC-9.
			if mfaHandler != nil {
				r.Route("/mfa", func(r chi.Router) {
					r.Get("/", mfaHandler.Status)
					r.Post("/enroll", mfaHandler.Enroll)
					r.Post("/confirm", mfaHandler.Confirm)
					r.Post("/disable", mfaHandler.Disable)
					r.Post("/recovery-codes", mfaHandler.RecoveryCodes)
				})
			}
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
	monitoringHandler *handler.MonitoringHandler,
	adminLogsHandler *handler.AdminLogsHandler,
	settingsHandler *handler.SettingsHandler,
	healthHandler *handler.HealthHandler,
	magicLinkHandler *handler.MagicLinkHandler, // nil-safe; Request endpoint registered here
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	appRepo repository.AppRepository,
	config RouterConfig,
) http.Handler {
	r := chi.NewRouter()

	// Global Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	// CorrelationID must run before the request logger so the correlation ID
	// is present in the context the logger reads (RFC-008).
	r.Use(middleware.CorrelationID())
	r.Use(logger.RequestLoggerMiddleware)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.AppVersion)

	// IP Blocking middleware (automatic defense)
	if config.IPBlockChecker != nil {
		r.Use(middleware.IPBlockMiddleware(config.IPBlockChecker, config.TrustedProxyCIDRs))
	}

	// CORS for admin API (H-06: wildcard + credentials disallowed)
	r.Use(corsHandler(config))

	r.Use(middleware.JSONContentType())

	// ==========================================
	// Health Routes (for internal monitoring)
	// ==========================================
	r.Get("/health", healthHandler.Health)
	r.Get("/health/liveness", healthHandler.Liveness)
	r.Get("/health/readiness", healthHandler.Readiness)
	r.Get("/version", healthHandler.Version)

	// ==========================================
	// Admin Authentication (public - no auth required)
	// ==========================================
	r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter, config.TrustedProxyCIDRs)).
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
				r.Delete("/", adminHandler.DeleteUser)
				r.Get("/apps", adminHandler.GetUserApps) // Get all apps user belongs to
				r.Get("/sessions", monitoringHandler.GetUserSessions)
				r.Post("/revoke-tokens", adminHandler.RevokeUserTokens)
				r.Post("/unlock", adminHandler.UnlockUser)
				r.Post("/block", adminHandler.BlockUser)
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

		// Security monitoring endpoints
		r.Route("/security", func(r chi.Router) {
			r.Get("/events", monitoringHandler.GetSecurityEvents)
			r.Get("/threats", monitoringHandler.GetThreatMetrics)
			r.Get("/geo", monitoringHandler.GetGeoAnalytics)

			// IP blocking
			r.Get("/blocked-ips", monitoringHandler.ListBlockedIPs)
			r.Post("/blocked-ips", monitoringHandler.BlockIP)
			r.Delete("/blocked-ips/{id}", monitoringHandler.UnblockIP)
			r.Get("/ip-reputation/{ip}", monitoringHandler.GetIPReputation)
		})

		// Real-time event streams
		r.Route("/events", func(r chi.Router) {
			r.Get("/stream", monitoringHandler.StreamEvents)
		})

		// Session management
		r.Route("/sessions", func(r chi.Router) {
			r.Get("/", monitoringHandler.ListSessions)
		})

		// Report generation
		r.Route("/reports", func(r chi.Router) {
			r.Post("/security", monitoringHandler.GenerateSecurityReport)
			r.Get("/{id}", monitoringHandler.GetReportStatus)
			r.Get("/{id}/download", monitoringHandler.DownloadReport)
		})

		// Alert management
		r.Route("/alerts", func(r chi.Router) {
			r.Get("/rules", monitoringHandler.ListAlertRules)
			r.Post("/rules", monitoringHandler.CreateAlertRule)
			r.Put("/rules/{id}", monitoringHandler.UpdateAlertRule)
			r.Delete("/rules/{id}", monitoringHandler.DeleteAlertRule)

			r.Get("/history", monitoringHandler.GetAlertHistory)
			r.Post("/{id}/acknowledge", monitoringHandler.AcknowledgeAlert)
		})

		// Token analytics
		r.Get("/tokens/stats", monitoringHandler.GetTokenStats)

		// ==========================================
		// Admin Audit Logs
		// ==========================================
		r.Route("/logs", func(r chi.Router) {
			// /export must be registered before /{id} so chi does not
			// treat the literal "export" as a numeric ID parameter.
			r.Get("/export", adminLogsHandler.ExportLogs)
			r.Get("/", adminLogsHandler.ListLogs)
			r.Get("/{id}", adminLogsHandler.GetLog)
		})

		// ==========================================
		// Server Settings / Config
		// ==========================================
		r.Route("/settings", func(r chi.Router) {
			r.Get("/config", settingsHandler.GetConfig)
			r.Get("/test-db", settingsHandler.TestDB)
			r.Get("/test-cache", settingsHandler.TestCache)
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

	// ==========================================
	// Service Account Routes (M2M client_credentials)
	// Protected by ServiceAccountMiddleware — no human user JWT required.
	// Token must carry sub="app:{id}" matching the {app_id} URL parameter.
	// ==========================================
	r.Route("/api/apps/{app_id}/service", func(r chi.Router) {
		r.Use(middleware.ServiceAccountMiddleware(appRepo, tokenService))
		r.Post("/users", appUsersHandler.CreateUser)

		// Magic-link request — only the authenticated app backend may trigger
		// magic-link emails.  The app identity is already proven by
		// ServiceAccountMiddleware (sub=app:{id} + URL cross-check).
		if magicLinkHandler != nil {
			r.Post("/magic-link", magicLinkHandler.Request)
		}
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
	mfaHandler *handler.MFAHandler,
	adminHandler *handler.AdminHandler,
	adminAuthHandler *handler.AdminAuthHandler,
	dashboardHandler *handler.DashboardHandler,
	healthHandler *handler.HealthHandler,
	appLogsHandler *handler.AppLogsHandler,
	monitoringHandler *handler.MonitoringHandler,
	adminLogsHandler *handler.AdminLogsHandler,
	settingsHandler *handler.SettingsHandler,
	webHandler *internalweb.WebHandler,
	magicLinkHandler *handler.MagicLinkHandler,
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	appRepo repository.AppRepository,
	config RouterConfig,
) http.Handler {
	r := chi.NewRouter()

	// Global Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	// CorrelationID must run before the request logger so the correlation ID
	// is present in the context the logger reads (RFC-008).
	r.Use(middleware.CorrelationID())
	r.Use(logger.RequestLoggerMiddleware)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(middleware.SecurityHeaders())

	// CORS for combined router (H-06: wildcard + credentials disallowed)
	r.Use(corsHandler(config))

	r.Use(middleware.JSONContentType())

	// Mount OAuth router
	oauthRouter := newOAuthRouter(authHandler, oauthHandler, webHandler, profileHandler, mfaHandler, healthHandler, magicLinkHandler, tokenService, userRepo, config)
	r.Mount("/", oauthRouter)

	// Mount Admin router under /admin prefix (for single-port mode)
	adminRouter := newAdminRouter(adminHandler, adminAuthHandler, dashboardHandler, appUsersHandler, appLogsHandler, monitoringHandler, adminLogsHandler, settingsHandler, healthHandler, magicLinkHandler, tokenService, userRepo, userAppRoleRepo, appRepo, config)
	r.Mount("/manage", adminRouter)

	return r
}
