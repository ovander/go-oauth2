package main

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/config"
	"github.com/ovandermoten/go-oauth2/internal/database/migrate"
	"github.com/ovandermoten/go-oauth2/internal/handler"
	internalhttp "github.com/ovandermoten/go-oauth2/internal/http"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/service"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"github.com/ovandermoten/go-oauth2/internal/web"
	"github.com/ovandermoten/go-oauth2/pkg/database"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// App holds the application dependencies
type App struct {
	// Single-port mode (backwards compatible)
	Router http.Handler

	// Dual-port mode (recommended for production)
	OAuthRouter http.Handler // Public OAuth/OIDC server
	AdminRouter http.Handler // Internal admin API

	DB *gorm.DB

	// Cleanup functions for graceful shutdown
	codeStore         *auth.CodeStore
	loginRateLimiter  *middleware.RateLimiter
	signupRateLimiter *middleware.RateLimiter
	// MED-05: tokenRateLimiter protects POST /oauth/token.  Stored here so
	// it participates in the graceful-shutdown Stop() sequence alongside the
	// other rate limiters.
	tokenRateLimiter *middleware.RateLimiter
	autoDefense      *service.AutoDefenseService
	ipBlockChecker   *middleware.IPBlockChecker
	// keyRotationStop stops the scheduled key-rotation goroutine on shutdown.
	// Nil when scheduled rotation is disabled (KeyRotationInterval == 0).
	keyRotationStop func()
}

// keyRetentionFor resolves the retired-key retention window: the configured
// value when positive, otherwise the refresh-token TTL so retired keys always
// outlive the longest-lived token that could still need them for verification.
func keyRetentionFor(retention, refreshTTL time.Duration) time.Duration {
	if retention > 0 {
		return retention
	}
	return refreshTTL
}

// mustParseTrustedProxies parses the comma-separated TRUSTED_PROXIES config value
// into a slice of *net.IPNet.  The server fatals on invalid input.
// Returns nil (safe default) when the setting is empty — proxy headers are then
// never trusted and RemoteAddr is always used as-is.
func mustParseTrustedProxies(raw string) []*net.IPNet {
	cidrs, err := middleware.ParseTrustedProxyCIDRs(raw)
	if err != nil {
		logger.Fatalf("Invalid TRUSTED_PROXIES setting: %v", err)
	}
	if len(cidrs) > 0 {
		logger.Infof("Trusting %d proxy CIDR(s) for X-Forwarded-For/X-Real-IP", len(cidrs))
	} else {
		logger.Info("No trusted proxies configured — using RemoteAddr for client IP (safe default)")
	}
	return cidrs
}

// parseAllowedOrigins converts the comma-separated ALLOWED_ORIGINS config value
// into the slice expected by RouterConfig.  Returns ["*"] when the setting is
// empty so that development works out of the box — the router will suppress
// AllowCredentials automatically when the wildcard is present (H-06 fix).
func parseAllowedOrigins(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		logger.Info("ALLOWED_ORIGINS not set — CORS wildcard active without credentials (safe default)")
		return []string{"*"}
	}
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, o := range parts {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}
	logger.Infof("CORS allowed origins: %v", origins)
	return origins
}

// Stop gracefully stops all background goroutines
func (a *App) Stop() {
	if a.codeStore != nil {
		a.codeStore.Stop()
	}
	if a.loginRateLimiter != nil {
		a.loginRateLimiter.Stop()
	}
	if a.signupRateLimiter != nil {
		a.signupRateLimiter.Stop()
	}
	if a.tokenRateLimiter != nil {
		a.tokenRateLimiter.Stop()
	}
	if a.autoDefense != nil {
		a.autoDefense.Stop()
	}
	if a.ipBlockChecker != nil {
		a.ipBlockChecker.Stop()
	}
	if a.keyRotationStop != nil {
		a.keyRotationStop()
	}
}

func Bootstrap(cfg *config.Config) *App {
	// ==========================================
	// Database
	// ==========================================
	// L-06 fix: Config.DBTimeout was parsed from DB_TIMEOUT_SECONDS but never
	// forwarded to the connector.  Wire it as the maximum idle-connection
	// lifetime so connections that have been unused for longer than the
	// configured timeout are recycled rather than held indefinitely.
	dbCfg := database.DefaultConnectionConfig(cfg.DBPoolSize)
	if cfg.DBTimeout > 0 {
		dbCfg.ConnMaxIdleTime = cfg.DBTimeout
	}
	db := database.ConnectWithConfig(cfg.DatabaseURL, dbCfg)

	// ==========================================
	// Versioned schema migrations (always run — idempotent)
	// ==========================================
	// M-02 fix: ad-hoc schema fixups that previously ran inline in bootstrap
	// are now tracked migrations that execute exactly once per environment.
	if err := migrate.Run(db); err != nil {
		logger.Fatalf("Schema migration failed: %v", err)
	}

	// ==========================================
	// Auto-migrate database schema (opt-in only)
	// ==========================================
	// M-01 fix: GORM AutoMigrate diffs the live schema against the models and
	// applies changes on every startup.  In production this can silently add
	// columns or indexes at an inconvenient time.  It is now gated behind the
	// AUTO_MIGRATE=true environment variable.
	//
	// Deployment workflow:
	//   - First deploy / schema change: set AUTO_MIGRATE=true, start, then unset.
	//   - Normal restarts: leave AUTO_MIGRATE unset (defaults to false).
	if cfg.AutoMigrate {
		if cfg.IsProduction() {
			logger.Warn("⚠️  AUTO_MIGRATE=true in production — schema will be modified on startup")
		}
		if err := db.AutoMigrate(
			&model.User{},
			&model.App{},
			&model.UserAppRole{},
			&model.AdminLog{},
			&model.AppActivityLog{},
			&model.AuthorizationCode{},
			&model.UsedToken{},
			&model.SecurityAuditLog{},
			&model.AlertRule{},
			&model.TriggeredAlert{},
			&model.BlockedIP{},
			&model.MagicLinkToken{},
		); err != nil {
			logger.Fatalf("Failed to auto-migrate database: %v", err)
		}
		logger.Info("✅ Database schema auto-migrated successfully")
	} else {
		logger.Info("AUTO_MIGRATE=false — skipping GORM schema diffing (set AUTO_MIGRATE=true to apply model changes)")
	}

	// ==========================================
	// Key Manager
	// ==========================================
	keyManager, err := auth.NewKeyManager(cfg.KeysPath)
	if err != nil {
		panic("failed to initialize key manager: " + err.Error())
	}

	// Scheduled key rotation + retired-key pruning (RFC-002 / EPIC-3).
	// Disabled by default (KeyRotationInterval == 0): keys then rotate only on
	// explicit operator action, preserving prior behaviour.
	var keyRotationStop func()
	if cfg.KeyRotationInterval > 0 {
		retention := keyRetentionFor(cfg.KeyRetention, cfg.RefreshTokenTTL)
		if cfg.KeyRotationInterval > cfg.RefreshTokenTTL {
			logger.WithFields(logger.Fields{
				"rotation_interval": cfg.KeyRotationInterval.String(),
				"refresh_token_ttl": cfg.RefreshTokenTTL.String(),
			}).Warn("RFC-002: KEY_ROTATION_INTERVAL exceeds REFRESH_TOKEN_TTL — a compromised key could outlive the next rotation; consider a shorter interval")
		}
		keyRotationStop = keyManager.StartRotationScheduleWithRetention(cfg.KeyRotationInterval, retention)
		logger.WithFields(logger.Fields{
			"rotation_interval": cfg.KeyRotationInterval.String(),
			"retention":         retention.String(),
		}).Info("RFC-002: scheduled key rotation enabled")
	}

	// ==========================================
	// Token Service
	// ==========================================
	tokenService := auth.NewTokenService(keyManager, auth.TokenConfig{
		Issuer:          cfg.OAuthIssuer,
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		EmailTokenTTL:   cfg.EmailTokenTTL,
		ResetTokenTTL:   cfg.ResetTokenTTL,
		InviteTokenTTL:  cfg.InviteTokenTTL,
	})

	// ==========================================
	// Repositories
	// ==========================================
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewAppRepository(db)
	userAppRoleRepo := repository.NewUserAppRoleRepository(db)
	adminLogRepo := repository.NewAdminLogRepository(db)
	appActivityLogRepo := repository.NewAppActivityLogRepository(db)
	authCodeRepo := repository.NewAuthorizationCodeRepository(db)
	usedTokenRepo := repository.NewUsedTokenRepository(db)
	securityAuditRepo := repository.NewSecurityAuditLogRepository(db)

	magicLinkRepo := repository.NewMagicLinkRepository(db)

	// Monitoring repositories
	alertRuleRepo := repository.NewAlertRuleRepository(db)
	triggeredAlertRepo := repository.NewTriggeredAlertRepository(db)
	blockedIPRepo := repository.NewBlockedIPRepository(db)

	// ==========================================
	// Code Store (database-backed with cleanup)
	// ==========================================
	codeStore := auth.NewCodeStore(authCodeRepo, auth.CodeStoreConfig{
		TTL:             10 * time.Minute,
		CleanupInterval: time.Minute,
	})

	// ==========================================
	// Services
	// ==========================================
	userService := service.NewUserService(userRepo)
	appService := service.NewAppService(appRepo)
	userAppRoleService := service.NewUserAppRoleService(userAppRoleRepo)
	adminLogService := service.NewAdminLogService(adminLogRepo)
	appActivityLogService := service.NewAppActivityLogService(appActivityLogRepo)

	// Email service (nil if SMTP not configured)
	var emailService service.EmailService
	if cfg.SMTPHost != "" {
		emailService = service.NewEmailService(service.EmailConfig{
			SMTPHost:     cfg.SMTPHost,
			SMTPPort:     cfg.SMTPPort,
			SMTPUsername: cfg.SMTPUsername,
			SMTPPassword: cfg.SMTPPassword,
			SMTPSecurity: cfg.SMTPSecurity,
			FromEmail:    cfg.FromEmail,
			FromName:     cfg.FromName,
			BaseURL:      cfg.OAuthIssuer,
		})
		logger.Info("✅ Email service configured with SMTP")
	} else {
		logger.Info("⚠️  Email service not configured (SMTP_HOST not set)")
	}

	// Use auth service with full features (single-use tokens + audit logging)
	authService := service.NewAuthServiceFull(
		userRepo,
		appRepo,
		userAppRoleRepo,
		usedTokenRepo,
		securityAuditRepo,
		tokenService,
		emailService,
		service.AuthServiceConfig{
			MaxFailedAttempts: cfg.MaxFailedAttempts,
			LockoutDuration:   time.Duration(cfg.LockoutDurationSecs) * time.Second,
		},
	)

	// M-09 fix: securityAuditService was created and immediately discarded.
	// The monitoring handler receives securityAuditRepo directly and does not
	// need a separate service wrapper here.  Remove the dead code.

	oauthService := service.NewOAuthService(
		userRepo,
		appRepo,
		userAppRoleRepo,
		codeStore,
		tokenService,
		keyManager,
		cfg.OAuthIssuer,
		securityAuditRepo,
		usedTokenRepo, // HIGH-04: single-use refresh token JTI tracking
	)

	// ==========================================
	// Template Service
	// ==========================================
	templateService := service.NewTemplateService()

	// ==========================================
	// GeoIP Service
	// ==========================================
	var geoIPService service.GeoIPService
	if cfg.GeoIPCityDBPath != "" {
		geoIPService = service.NewGeoIPService(service.GeoIPConfig{
			CityDBPath: cfg.GeoIPCityDBPath,
			ASNDBPath:  cfg.GeoIPASNDBPath,
		})
		logger.Info("GeoIP service initialized")
	} else {
		geoIPService = service.NewGeoIPServiceDisabled()
		logger.Info("GeoIP service running in fallback mode (no database configured)")
	}

	// ==========================================
	// Handlers
	// ==========================================
	authHandler := handler.NewAuthHandler(authService, userService, emailService, cfg.Environment, cfg.OAuthIssuer)
	oauthHandler := handler.NewOAuthHandler(oauthService, authService, appService, templateService, tokenService, cfg.OAuthIssuer, []byte(cfg.SecretKeyBase))
	appUsersHandler := handler.NewAppUsersHandler(userService, userAppRoleService, appService, adminLogService, emailService, tokenService, cfg.OAuthIssuer)
	profileHandler := handler.NewProfileHandler(userService)
	adminHandler := handler.NewAdminHandler(appService, userService, userAppRoleService, adminLogService, appActivityLogService, emailService)
	adminAuthHandler := handler.NewAdminAuthHandler(authService, userService)
	dashboardHandler := handler.NewDashboardHandler(db, userRepo, appRepo, userAppRoleRepo)
	healthHandler := handler.NewHealthHandler(db)
	appLogsHandler := handler.NewAppLogsHandler(appActivityLogService)
	monitoringHandler := handler.NewMonitoringHandler(db, alertRuleRepo, triggeredAlertRepo, blockedIPRepo, securityAuditRepo, geoIPService)
	adminLogsHandler := handler.NewAdminLogsHandler(db)
	settingsHandler := handler.NewSettingsHandler(cfg, db)

	// Magic link service (must be created before magicLinkHandler below)
	magicLinkService := service.NewMagicLinkService(
		magicLinkRepo,
		userRepo,
		appRepo,
		userAppRoleRepo,
		tokenService,
		emailService,
		cfg.OAuthIssuer,
		cfg.Environment,
	)
	magicLinkHandler := handler.NewMagicLinkHandler(magicLinkService, cfg.Environment)

	// Web handler for HTML auth pages
	webHandler, err := web.NewWebHandler(
		authService,
		userService,
		appRepo,
		emailService,
		tokenService,
		cfg.OAuthIssuer,
	)
	if err != nil {
		logger.Fatalf("Failed to create web handler: %v", err)
	}
	logger.Info("✅ Web handler initialized")

	// ==========================================
	// Auto-Defense System (automatic IP blocking)
	// ==========================================
	autoDefense := service.NewAutoDefenseService(
		blockedIPRepo,
		securityAuditRepo,
		service.DefaultAutoDefenseConfig(),
	)
	logger.Info("✅ Auto-defense system initialized")

	// IP Block Checker (middleware cache)
	ipBlockChecker := middleware.NewIPBlockChecker(
		blockedIPRepo,
		middleware.DefaultIPBlockCheckerConfig(),
	)
	logger.Info("✅ IP block checker initialized")

	// Connect auto-defense to IP block checker for immediate cache invalidation
	autoDefense.SetOnBlockCallback(func(ip string) {
		ipBlockChecker.InvalidateCache()
	})

	// Wire auto-defense to auth handlers
	authHandler.SetAutoDefenseService(autoDefense)
	adminAuthHandler.SetAutoDefenseService(autoDefense)

	// ==========================================
	// Rate Limiters (with graceful shutdown support)
	// ==========================================
	loginRateLimiter := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit:           cfg.RateLimitLogin,
		Window:          cfg.RateLimitLoginWindow,
		MaxEntries:      cfg.RateLimitMaxEntries,
		CleanupInterval: time.Minute,
	})

	signupRateLimiter := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit:           cfg.RateLimitSignup,
		Window:          cfg.RateLimitSignupWindow,
		MaxEntries:      cfg.RateLimitMaxEntries,
		CleanupInterval: time.Minute,
	})

	// MED-05: token endpoint rate limiter — nil when explicitly disabled
	// (RATE_LIMIT_TOKEN=0).  A nil limiter leaves the token endpoint unprotected;
	// the production Validate() warning fires in that case.
	var tokenRateLimiter *middleware.RateLimiter
	if cfg.RateLimitToken > 0 {
		tokenRateLimiter = middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
			Limit:           cfg.RateLimitToken,
			Window:          cfg.RateLimitTokenWindow,
			MaxEntries:      cfg.RateLimitMaxEntries,
			CleanupInterval: time.Minute,
		})
		logger.WithFields(logger.Fields{
			"limit":  cfg.RateLimitToken,
			"window": cfg.RateLimitTokenWindow.String(),
		}).Info("✅ Token endpoint rate limiter configured")
	} else {
		logger.Warn("⚠️  Token endpoint rate limiting disabled (RATE_LIMIT_TOKEN=0)")
	}

	// ==========================================
	// Router Configuration
	// ==========================================
	routerConfig := internalhttp.RouterConfig{
		AllowedOrigins:    parseAllowedOrigins(cfg.AllowedOrigins),
		LoginRateLimiter:  loginRateLimiter,
		SignupRateLimiter: signupRateLimiter,
		TokenRateLimiter:  tokenRateLimiter, // MED-05: nil only when explicitly disabled
		IPBlockChecker:    ipBlockChecker,
		TrustedProxyCIDRs: mustParseTrustedProxies(cfg.TrustedProxies),
	}

	// ==========================================
	// Create Routers
	// ==========================================
	// M-08 fix: build only the router(s) that will actually be used.
	// In single-port mode NewRouters (dual) is never used; in dual-port mode
	// NewRouter (combined) is never used.  Building both wastes memory and
	// registers routes that will never receive requests.
	if cfg.AdminPort != "" {
		// Dual-port mode: separate OAuth and Admin routers.
		routers := internalhttp.NewRouters(
			authHandler,
			oauthHandler,
			appUsersHandler,
			profileHandler,
			adminHandler,
			adminAuthHandler,
			dashboardHandler,
			healthHandler,
			appLogsHandler,
			monitoringHandler,
			adminLogsHandler,
			settingsHandler,
			webHandler,
			magicLinkHandler,
			tokenService,
			userRepo,
			userAppRoleRepo,
			appRepo,
			routerConfig,
		)
		return &App{
			OAuthRouter:       routers.OAuth,
			AdminRouter:       routers.Admin,
			DB:                db,
			codeStore:         codeStore,
			loginRateLimiter:  loginRateLimiter,
			signupRateLimiter: signupRateLimiter,
			tokenRateLimiter:  tokenRateLimiter, // MED-05
			autoDefense:       autoDefense,
			ipBlockChecker:    ipBlockChecker,
			keyRotationStop:   keyRotationStop,
		}
	}

	// Single-port mode: combined router only.
	combinedRouter := internalhttp.NewRouter(
		authHandler,
		oauthHandler,
		appUsersHandler,
		profileHandler,
		adminHandler,
		adminAuthHandler,
		dashboardHandler,
		healthHandler,
		appLogsHandler,
		monitoringHandler,
		adminLogsHandler,
		settingsHandler,
		webHandler,
		magicLinkHandler,
		tokenService,
		userRepo,
		userAppRoleRepo,
		appRepo,
		routerConfig,
	)
	return &App{
		Router:            combinedRouter,
		DB:                db,
		codeStore:         codeStore,
		loginRateLimiter:  loginRateLimiter,
		signupRateLimiter: signupRateLimiter,
		tokenRateLimiter:  tokenRateLimiter, // MED-05
		autoDefense:       autoDefense,
		ipBlockChecker:    ipBlockChecker,
		keyRotationStop:   keyRotationStop,
	}
}
