package main

import (
	"net/http"
	"time"

	"github.com/ovandermoten/go-oauth2/config"
	"github.com/ovandermoten/go-oauth2/internal/handler"
	internalhttp "github.com/ovandermoten/go-oauth2/internal/http"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/service"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
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
}

func Bootstrap(cfg *config.Config) *App {
	// ==========================================
	// Database
	// ==========================================
	db := database.Connect(cfg.DatabaseURL, cfg.DBPoolSize)

	// ==========================================
	// Auto-migrate database schema
	// ==========================================
	if err := db.AutoMigrate(
		&model.User{},
		&model.App{},
		&model.UserAppRole{},
		&model.AdminLog{},
		&model.AppActivityLog{},
		&model.AuthorizationCode{},
		&model.UsedToken{},
		&model.SecurityAuditLog{},
	); err != nil {
		logger.Fatalf("Failed to auto-migrate database: %v", err)
	}
	logger.Info("✅ Database schema migrated successfully")

	// ==========================================
	// Key Manager
	// ==========================================
	keyManager, err := auth.NewKeyManager(cfg.KeysPath)
	if err != nil {
		panic("failed to initialize key manager: " + err.Error())
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

	// Use auth service with full features (single-use tokens + audit logging)
	authService := service.NewAuthServiceFull(
		userRepo,
		appRepo,
		userAppRoleRepo,
		usedTokenRepo,
		securityAuditRepo,
		tokenService,
		service.AuthServiceConfig{
			MaxFailedAttempts: cfg.MaxFailedAttempts,
			LockoutDuration:   time.Duration(cfg.LockoutDurationSecs) * time.Second,
		},
	)

	// Security audit service for querying logs
	securityAuditService := service.NewSecurityAuditService(securityAuditRepo)
	_ = securityAuditService // Available for admin handlers if needed

	oauthService := service.NewOAuthService(
		userRepo,
		appRepo,
		userAppRoleRepo,
		codeStore,
		tokenService,
		keyManager,
		cfg.OAuthIssuer,
	)

	// ==========================================
	// Handlers
	// ==========================================
	authHandler := handler.NewAuthHandler(authService, cfg.Environment, cfg.OAuthIssuer)
	oauthHandler := handler.NewOAuthHandler(oauthService, cfg.OAuthIssuer)
	appUsersHandler := handler.NewAppUsersHandler(userService, userAppRoleService, adminLogService, tokenService)
	profileHandler := handler.NewProfileHandler(userService)
	adminHandler := handler.NewAdminHandler(appService, userService, adminLogService, appActivityLogService)
	adminAuthHandler := handler.NewAdminAuthHandler(authService)
	healthHandler := handler.NewHealthHandler(db)
	appLogsHandler := handler.NewAppLogsHandler(appActivityLogService)

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

	// ==========================================
	// Router Configuration
	// ==========================================
	routerConfig := internalhttp.RouterConfig{
		AllowedOrigins:    []string{"*"}, // Configure in production
		LoginRateLimiter:  loginRateLimiter,
		SignupRateLimiter: signupRateLimiter,
	}

	// ==========================================
	// Create Routers
	// ==========================================
	// Use NewRouters for dual-port mode (production recommended)
	routers := internalhttp.NewRouters(
		authHandler,
		oauthHandler,
		appUsersHandler,
		profileHandler,
		adminHandler,
		adminAuthHandler,
		healthHandler,
		appLogsHandler,
		tokenService,
		userRepo,
		userAppRoleRepo,
		routerConfig,
	)

	// Also create combined router for single-port mode (backwards compatible)
	combinedRouter := internalhttp.NewRouter(
		authHandler,
		oauthHandler,
		appUsersHandler,
		profileHandler,
		adminHandler,
		adminAuthHandler,
		healthHandler,
		appLogsHandler,
		tokenService,
		userRepo,
		userAppRoleRepo,
		routerConfig,
	)

	return &App{
		Router:            combinedRouter,
		OAuthRouter:       routers.OAuth,
		AdminRouter:       routers.Admin,
		DB:                db,
		codeStore:         codeStore,
		loginRateLimiter:  loginRateLimiter,
		signupRateLimiter: signupRateLimiter,
	}
}
