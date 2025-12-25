package main

import (
	"net/http"
	"time"

	"github.com/socrate-auth/go-oauth/config"
	"github.com/socrate-auth/go-oauth/internal/handler"
	internalhttp "github.com/socrate-auth/go-oauth/internal/http"
	"github.com/socrate-auth/go-oauth/internal/middleware"
	"github.com/socrate-auth/go-oauth/internal/repository"
	"github.com/socrate-auth/go-oauth/internal/service"
	"github.com/socrate-auth/go-oauth/internal/shared/auth"
	"github.com/socrate-auth/go-oauth/pkg/database"
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
}

func Bootstrap(cfg *config.Config) *App {
	// ==========================================
	// Database
	// ==========================================
	db := database.Connect(cfg.DatabaseURL, cfg.DBPoolSize)

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
	// Code Store (10 minute TTL for auth codes)
	// ==========================================
	codeStore := auth.NewCodeStore(10 * time.Minute)

	// ==========================================
	// Repositories
	// ==========================================
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewAppRepository(db)
	userAppRoleRepo := repository.NewUserAppRoleRepository(db)
	adminLogRepo := repository.NewAdminLogRepository(db)
	appActivityLogRepo := repository.NewAppActivityLogRepository(db)

	// ==========================================
	// Services
	// ==========================================
	userService := service.NewUserService(userRepo)
	appService := service.NewAppService(appRepo)
	userAppRoleService := service.NewUserAppRoleService(userAppRoleRepo)
	adminLogService := service.NewAdminLogService(adminLogRepo)
	appActivityLogService := service.NewAppActivityLogService(appActivityLogRepo)

	authService := service.NewAuthService(
		userRepo,
		appRepo,
		userAppRoleRepo,
		tokenService,
		service.AuthServiceConfig{
			MaxFailedAttempts: cfg.MaxFailedAttempts,
			LockoutDuration:   time.Duration(cfg.LockoutDurationSecs) * time.Second,
		},
	)

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
	healthHandler := handler.NewHealthHandler(db)
	appLogsHandler := handler.NewAppLogsHandler(appActivityLogService)

	// ==========================================
	// Rate Limiters
	// ==========================================
	loginRateLimiter := middleware.NewRateLimiter(cfg.RateLimitLogin, cfg.RateLimitLoginWindow)
	signupRateLimiter := middleware.NewRateLimiter(cfg.RateLimitSignup, cfg.RateLimitSignupWindow)

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
		healthHandler,
		appLogsHandler,
		tokenService,
		userRepo,
		userAppRoleRepo,
		routerConfig,
	)

	return &App{
		Router:      combinedRouter,
		OAuthRouter: routers.OAuth,
		AdminRouter: routers.Admin,
		DB:          db,
	}
}
