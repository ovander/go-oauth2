package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ovander/go-oauth2/config"
	"github.com/ovander/go-oauth2/internal/cluster"
	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/handler"
	internalhttp "github.com/ovander/go-oauth2/internal/http"
	"github.com/ovander/go-oauth2/internal/metrics"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/internal/shared/auth/dpop"
	"github.com/ovander/go-oauth2/internal/shared/auth/tokenexchange"
	"github.com/ovander/go-oauth2/internal/state"
	"github.com/ovander/go-oauth2/internal/version"
	"github.com/ovander/go-oauth2/internal/web"
	"github.com/ovander/go-oauth2/pkg/database"
	"github.com/ovander/go-oauth2/pkg/logger"
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
	loginRateLimiter  middleware.Limiter
	signupRateLimiter middleware.Limiter
	// MED-05: tokenRateLimiter protects POST /oauth/token.  Stored here so
	// it participates in the graceful-shutdown Stop() sequence alongside the
	// other rate limiters.
	tokenRateLimiter middleware.Limiter
	autoDefense      *service.AutoDefenseService
	ipBlockChecker   *middleware.IPBlockChecker
	// keyRotationStop stops the scheduled key-rotation goroutine on shutdown.
	// Nil when scheduled rotation is disabled (KeyRotationInterval == 0).
	keyRotationStop func()
	// auditIntegrityStop stops the scheduled audit-integrity scan on shutdown.
	// Nil when the scan is disabled (AuditIntegrityScanInterval == 0).
	auditIntegrityStop func()
	// usedTokenCleanupStop stops the scheduled used-token pruning on shutdown.
	// Nil when cleanup is disabled (UsedTokenCleanupInterval == 0).
	usedTokenCleanupStop func()
	// webhookCacheStop stops the webhook subscription cache refresh (A3).
	// Nil when webhooks are disabled (WEBHOOKS_MODE=off).
	webhookCacheStop func()
	// webhookDispatchStop stops the webhook delivery dispatcher (A3 part 2).
	// Nil when webhooks are disabled.
	webhookDispatchStop func()
	// auditAsync is the asynchronous audit appender (AUDIT_WRITE_MODE=async),
	// drained last on shutdown. Nil in sync mode.
	auditAsync *repository.AsyncAuditRepository
	// stateSweepStop stops the shared-state sweeper (B4). Nil unless
	// STATE_BACKEND=postgres.
	stateSweepStop func()
	// policyDecisionSweepStop stops the A4 decision-log retention sweep.
	// Nil when retention is disabled (POLICY_DECISION_RETENTION_DAYS=0).
	policyDecisionSweepStop func()
	// dpopReplayCache backs DPoP observe-mode replay detection; nil when DPoP is
	// off. Stopped on shutdown.
	dpopReplayCache *dpop.MemoryReplayCache
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
// Returns nil when the setting is empty or "none" — proxy headers are then
// never trusted and RemoteAddr is always used as-is. Note that behind the
// documented Caddy/BFF topology that means every request attributes to the
// proxy's own address (rate limits and IP blocks become global), so the
// config default is loopback rather than empty.
func mustParseTrustedProxies(raw string) []*net.IPNet {
	cidrs, err := middleware.ParseTrustedProxyCIDRs(raw)
	if err != nil {
		logger.Fatalf("Invalid TRUSTED_PROXIES setting: %v", err)
	}
	if len(cidrs) > 0 {
		logger.WithFields(logger.Fields{"trusted_proxies": raw}).
			Info("Trusting proxy CIDR(s) for X-Forwarded-For/X-Real-IP; all other peers attribute to RemoteAddr")
	} else {
		logger.Warn("TRUSTED_PROXIES is none/empty — using RemoteAddr for every client IP; " +
			"behind a reverse proxy this collapses rate limits, IP blocks and audit attribution onto the proxy address")
	}
	return cidrs
}

// LogStartupSummary emits a single structured line summarising the server's
// effective configuration — version, environment, ports, the security posture
// (DPoP / token-exchange / refresh-reuse / audience / admin-MFA modes), the
// admin-console hardening flags, and the scheduled-job intervals. It is the one
// line an operator greps to confirm how a deployment is configured. Production
// safety warnings are emitted separately so they stand out.
func LogStartupSummary(cfg *config.Config) {
	dur := func(d time.Duration) string {
		if d <= 0 {
			return "disabled"
		}
		return d.String()
	}
	mode := "single-port"
	if cfg.AdminPort != "" {
		mode = "dual-port"
	}

	logger.WithFields(logger.Fields{
		"version":     version.Version,
		"commit":      version.Commit,
		"environment": cfg.Environment,
		"issuer":      cfg.OAuthIssuer,
		"mode":        mode,
		"oauth_port":  cfg.Port,
		"admin_port":  cfg.AdminPort,
		"log_level":   logger.Logger.GetLevel().String(),
		// Security posture (observe → enforce rollout flags).
		"dpop_mode":               cfg.DPoPMode,
		"token_exchange_mode":     cfg.TokenExchangeMode,
		"refresh_reuse_mode":      cfg.RefreshReuseMode,
		"audience_mode":           cfg.AudienceMode,
		"admin_mfa_policy":        cfg.AdminMFAPolicy,
		"admin_app_signin_policy": cfg.AdminAppSignInPolicy,
		"admin_api_audience_mode": cfg.AdminAPIAudienceMode,
		"audit_write_mode":        cfg.AuditWriteMode,
		"policy_mode":             cfg.PolicyMode,
		// Admin-console session hardening.
		"admin_console_pkce":   cfg.AdminConsoleClientID != "",
		"admin_elevation":      dur(cfg.AdminElevationMaxAge),
		"admin_password_login": cfg.AdminPasswordLoginEnabled,
		// Scheduled background jobs.
		"key_rotation":         dur(cfg.KeyRotationInterval),
		"audit_integrity_scan": dur(cfg.AuditIntegrityScanInterval),
		"used_token_cleanup":   dur(cfg.UsedTokenCleanupInterval),
	}).Info("✅ Socrate initialized — effective configuration")

	// Production safety: surface risky-but-allowed settings so they are obvious
	// in the logs of a real deployment.
	if cfg.IsProduction() {
		if !strings.HasPrefix(cfg.OAuthIssuer, "https://") {
			logger.Warn("⚠️  production issuer is not https:// — tokens and cookies are not transport-secured")
		}
		if cfg.AdminPasswordLoginEnabled {
			logger.Warn("⚠️  /api/admin/login (deprecated password flow) is enabled in production — set ADMIN_PASSWORD_LOGIN_ENABLED=false once the admin console is on PKCE")
		}
	}
}

// splitCSV splits a comma-separated config value into trimmed, non-empty
// entries. Returns nil for an empty string.
func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
	if a.auditIntegrityStop != nil {
		a.auditIntegrityStop()
	}
	if a.usedTokenCleanupStop != nil {
		a.usedTokenCleanupStop()
	}
	if a.webhookCacheStop != nil {
		a.webhookCacheStop()
	}
	if a.webhookDispatchStop != nil {
		a.webhookDispatchStop()
	}
	if a.stateSweepStop != nil {
		a.stateSweepStop()
	}
	if a.policyDecisionSweepStop != nil {
		a.policyDecisionSweepStop()
	}
	if a.dpopReplayCache != nil {
		a.dpopReplayCache.Stop()
	}
	// Last: every worker above may still write audit rows. Drain the queue
	// before main closes the database.
	if a.auditAsync != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := a.auditAsync.Close(ctx); err != nil {
			logger.Errorf("audit: %d queued security events not written at shutdown: %v", a.auditAsync.Pending(), err)
		}
		cancel()
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
	dbCfg.LogLevel = database.ParseGormLogLevel(cfg.DBLogLevel)
	if cfg.DBTimeout > 0 {
		dbCfg.ConnMaxIdleTime = cfg.DBTimeout
	}
	db := database.ConnectWithConfig(cfg.DatabaseURL, dbCfg)
	metrics.SetBuildInfo(version.Version, version.Commit)
	if sqlDB, dbErr := db.DB(); dbErr == nil {
		metrics.RegisterDBStats(sqlDB.Stats)
	}

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
			&model.MFARecoveryCode{},
			&model.SecurityReport{},
		); err != nil {
			logger.Fatalf("Failed to auto-migrate database: %v", err)
		}
		logger.Info("✅ Database schema auto-migrated successfully")
	} else {
		logger.Info("AUTO_MIGRATE=false — skipping GORM schema diffing (set AUTO_MIGRATE=true to apply model changes)")
	}

	// B5: with STATE_BACKEND=postgres the periodic jobs below are gated on a
	// PostgreSQL advisory lock, so exactly one instance runs each tick. A nil
	// handle (single-instance, the default) leaves them running on every tick
	// exactly as before — the gate is opt-in with the same switch that makes
	// the request-path state shared, because the two only make sense together.
	var jobDB *gorm.DB
	if cfg.StateBackend == state.BackendPostgres {
		jobDB = db
	}

	// ==========================================
	// Key Manager
	// ==========================================
	keyManager, err := auth.NewKeyManager(cfg.KeysPath)
	if err == nil {
		metrics.SetSigningKeyCreatedAt(keyManager.CurrentKeyCreatedAt)
	}
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
		// B5: rotation must happen once per cluster, not once per instance —
		// N instances on the same schedule would burn through the JWKS ring N
		// times as fast and retire keys that tokens in flight still need.
		keyRotationStop = cluster.Every(jobDB, cluster.LockKeyRotation, "key_rotation",
			cfg.KeyRotationInterval, func(context.Context) error {
				if err := keyManager.RotateKey(); err != nil {
					return err
				}
				if retention > 0 {
					// A pruning failure is worth logging but must not fail the
					// tick: the rotation itself already succeeded, and retrying
					// it would mint a second key.
					if _, err := keyManager.PruneRetiredKeys(retention); err != nil {
						logger.WithFields(logger.Fields{"error": err.Error()}).
							Warn("B5: retired-key pruning failed after rotation")
					}
				}
				return nil
			})
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
		AudienceMode:    cfg.AudienceMode, // RFC-001 / EPIC-7
	})
	// A2: project each client's claim-mapping policy into its tokens, under a
	// namespace so a mapping can never shadow a standard claim. Inert until a
	// client registers a mapping.
	claimsEnricher := auth.NewMappingEnricher(cfg.ClaimsNamespace)
	tokenService.SetClaimsEnricher(claimsEnricher)
	logger.WithFields(logger.Fields{
		"claims_namespace": claimsEnricher.Namespace(),
	}).Info("A2: custom claim mapping enabled")

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
	// RFC-007: stamp a tamper-evidence HMAC on each audit row, keyed by
	// SECRET_KEY_BASE (held in config, never in the DB). Empty secret disables it.
	// B1: every persisted security event is also a Prometheus counter.
	auditRepoBase := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, []byte(cfg.SecretKeyBase))
	// AUDIT_WRITE_MODE=async: a background writer appends the rows in batches,
	// so a request no longer waits on the audit chain lock and its commit.
	// Drained last at shutdown (App.Stop).
	var auditAsync *repository.AsyncAuditRepository
	if cfg.AuditWriteMode == "async" {
		a, err := repository.NewAsyncAuditRepository(auditRepoBase, repository.AsyncAuditConfig{
			OnSyncFallback: metrics.AuditAsyncSyncFallback,
			OnBatch:        metrics.AuditAsyncBatch,
		})
		if err != nil {
			logger.Fatalf("bootstrap: %v", err)
		}
		auditAsync, auditRepoBase = a, a
	}
	securityAuditRepo := metrics.InstrumentAuditRepo(auditRepoBase)

	// A3: webhook subscriptions and the delivery outbox. The outbox producer is
	// installed on the *undecorated* audit repository, because it must run
	// inside that repository's transaction — the metrics decorator only wraps
	// the call. With WEBHOOKS_MODE=off (the default) the producer is installed
	// but enqueues nothing, so the audit write path is byte-for-byte as before.
	webhookRepo := repository.NewWebhookRepository(db)
	webhookService := service.NewWebhookService(webhookRepo, []byte(cfg.SecretKeyBase))
	var webhookCacheStop func()
	if setter, ok := auditRepoBase.(repository.AuditOutboxSetter); ok {
		setter.SetOutboxWriter(service.NewWebhookOutbox(webhookService, cfg.WebhooksEnabled))
	}
	var webhookDispatchStop func()
	if cfg.WebhooksEnabled {
		webhookCacheStop = webhookService.StartCacheRefresh(cfg.WebhookCacheRefresh)
		// A3 part 2: drain the outbox. Claiming uses FOR UPDATE SKIP LOCKED, so
		// several instances can run this concurrently without double-sending.
		webhookDispatchStop = service.NewWebhookDispatcher(webhookRepo, webhookService, service.DispatcherConfig{
			MaxAttempts:  cfg.WebhookMaxAttempts,
			BatchSize:    cfg.WebhookBatchSize,
			PollInterval: cfg.WebhookPollInterval,
			SendTimeout:  cfg.WebhookSendTimeout,
		}).Start()
		logger.WithFields(logger.Fields{
			"cache_refresh": cfg.WebhookCacheRefresh.String(),
			"poll_interval": cfg.WebhookPollInterval.String(),
			"max_attempts":  cfg.WebhookMaxAttempts,
			"batch_size":    cfg.WebhookBatchSize,
			"send_timeout":  cfg.WebhookSendTimeout.String(),
		}).Info("A3: webhook outbox and dispatcher enabled")
	}

	// RFC-007: optionally run the audit-row integrity scan on a timer. Disabled
	// by default (AuditIntegrityScanInterval == 0).
	var auditIntegrityStop func()
	if cfg.AuditIntegrityScanInterval > 0 {
		scanner := service.NewAuditIntegrityScanner(securityAuditRepo, []byte(cfg.SecretKeyBase))
		lookback := cfg.AuditIntegrityScanLookback
		auditIntegrityStop = cluster.Every(jobDB, cluster.LockAuditScan, "audit_integrity_scan",
			cfg.AuditIntegrityScanInterval, func(ctx context.Context) error {
				_, _, err := scanner.Scan(ctx, time.Now().Add(-lookback))
				return err
			})
		logger.WithFields(logger.Fields{
			"interval": cfg.AuditIntegrityScanInterval.String(),
			"lookback": cfg.AuditIntegrityScanLookback.String(),
		}).Info("RFC-007: scheduled audit integrity scan enabled")
	}

	// EPIC-14: prune expired rows from used_tokens (single-use JTIs + revocation
	// blacklist) on a timer so the table does not grow without bound. Enabled by
	// default (1h); disabled when UsedTokenCleanupInterval == 0.
	var usedTokenCleanupStop func()
	if cfg.UsedTokenCleanupInterval > 0 {
		cleaner := service.NewUsedTokenCleaner(usedTokenRepo)
		usedTokenCleanupStop = cluster.Every(jobDB, cluster.LockUsedTokenSweep, "used_token_cleanup",
			cfg.UsedTokenCleanupInterval, func(ctx context.Context) error {
				_, err := cleaner.Cleanup(ctx)
				return err
			})
		logger.WithFields(logger.Fields{
			"interval": cfg.UsedTokenCleanupInterval.String(),
		}).Info("EPIC-14: scheduled used-token cleanup enabled")
	}

	magicLinkRepo := repository.NewMagicLinkRepository(db)
	mfaRecoveryRepo := repository.NewMFARecoveryCodeRepository(db)

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

	// MFA (TOTP) service — shared by the enrollment handler and login step-up.
	mfaService := service.NewMFAService(userRepo, mfaRecoveryRepo, []byte(cfg.SecretKeyBase), cfg.OAuthIssuer)

	// Use auth service with full features (single-use tokens + audit logging).
	// WithMFA enables login step-up for MFA-enrolled users.
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
			AdminMFAPolicy:    cfg.AdminMFAPolicy,
		},
	).WithMFA(mfaService)

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
		cfg.TokenExchangeMode,
		cfg.ImpersonationTokenTTL,   // EPIC-17: time-box impersonated tokens
		cfg.ImpersonationStepUpMode, // EPIC-17: impersonation step-up (subject freshness)
		cfg.ImpersonationMaxAuthAge,
		cfg.DelegationStepUpMode, // EPIC-17: delegation step-up (actor MFA)
		cfg.RefreshReuseMode,     // RFC 9700: refresh-token reuse detection
		cfg.ScopePolicyMode,      // A1: per-client allowed_scopes policy
	)

	// Single refresh code path: POST /api/auth/refresh delegates to the hardened
	// /oauth/token refresh grant (rotation + single-use/replay detection +
	// token-family revocation + DPoP binding) instead of a separate, weaker
	// implementation. Wire the granter now that the OAuth service exists.
	// Both assertions hold by construction (*authService / *oauthService); a
	// failure is a wiring bug, so fail fast rather than run an unhardened path.
	granter, ok := oauthService.(service.RefreshGranter)
	if !ok {
		logger.Fatalf("bootstrap: OAuth service does not implement RefreshGranter")
	}
	rg, ok := authService.(interface {
		SetRefreshGranter(service.RefreshGranter)
	})
	if !ok {
		logger.Fatalf("bootstrap: auth service does not support SetRefreshGranter")
	}
	rg.SetRefreshGranter(granter)

	// ADMIN_APP_SIGNIN_POLICY: one policy for the hosted login (auth service)
	// and for code issuance and refresh (OAuth service).
	adminAppSignIn := service.NewAdminAppSignInPolicy(cfg.AdminAppSignInPolicy, cfg.ConsoleClientIDs())
	for _, svc := range []any{authService, oauthService} {
		ps, ok := svc.(interface {
			SetAdminAppSignInPolicy(service.AdminAppSignInPolicy)
		})
		if !ok {
			logger.Fatalf("bootstrap: %T does not support SetAdminAppSignInPolicy", svc)
		}
		ps.SetAdminAppSignInPolicy(adminAppSignIn)
	}

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
		logger.Debug("GeoIP service initialized")
	} else {
		geoIPService = service.NewGeoIPServiceDisabled()
		logger.Info("GeoIP service running in fallback mode (no database configured)")
	}

	// ==========================================
	// Handlers
	// ==========================================
	authHandler := handler.NewAuthHandler(authService, userService, emailService, cfg.Environment, cfg.OAuthIssuer)
	oauthHandler := handler.NewOAuthHandler(oauthService, authService, appService, templateService, tokenService, cfg.OAuthIssuer, []byte(cfg.SecretKeyBase))
	// Advertise DPoP support in OIDC discovery only when it is enabled
	// (RFC 9449 §5.1). The dpop package supports ES256.
	if cfg.DPoPMode != "off" && cfg.DPoPMode != "" {
		oauthHandler.SetDPoPSigningAlgs([]string{"ES256"})
	}
	oauthHandler.SetJWKSCacheMaxAge(int(cfg.JWKSCacheMaxAge.Seconds()))
	// Tier-0 admin session hardening: when an admin-console client is configured,
	// deliver its refresh token as an HttpOnly cookie (set/read at /oauth/token,
	// cleared at logout). Secure in production. Empty client id leaves it off.
	if cfg.AdminConsoleClientID != "" {
		oauthHandler.SetRefreshCookie(cfg.AdminConsoleClientID, cfg.RefreshTokenTTL, cfg.IsProduction())
		authHandler.SetRefreshCookie(true, cfg.IsProduction())
	}
	// Advertise the RFC 8693 token-exchange grant in discovery only when it can
	// actually be issued (enforce). In shadow it is non-issuing, so advertising
	// would mislead clients.
	if cfg.TokenExchangeMode == "enforce" {
		oauthHandler.SetExtraGrantTypes([]string{tokenexchange.GrantType})
	}
	appUsersHandler := handler.NewAppUsersHandler(userService, userAppRoleService, appService, adminLogService, emailService, tokenService, cfg.OAuthIssuer)
	profileHandler := handler.NewProfileHandler(userService)
	mfaHandler := handler.NewMFAHandler(mfaService, userService) // P3-9: disable needs re-auth
	// #203: AdminHandler emits client-lifecycle changes as alertable security
	// events; give it a security audit service over the same repo.
	adminSecurityAuditService := service.NewSecurityAuditService(securityAuditRepo)
	adminHandler := handler.NewAdminHandler(appService, userService, userAppRoleService, adminLogService, appActivityLogService, emailService, adminSecurityAuditService)
	adminAuthHandler := handler.NewAdminAuthHandler(authService, userService)
	// Tier-0 step-up: wire the re-authentication backend for POST /api/admin/elevate.
	if ra, ok := authService.(service.Reauthenticator); ok {
		adminAuthHandler.SetReauthenticator(ra)
	}
	// Tier-0: refuse the deprecated /api/admin/login password flow once the admin
	// console is on Authorization Code + PKCE (default keeps it enabled).
	adminAuthHandler.SetPasswordLoginDisabled(!cfg.AdminPasswordLoginEnabled)
	// Tier-0: idempotently register the first-party admin-console public PKCE
	// client from config (no-op unless both client id and redirect URIs are set).
	if _, err := service.EnsureAdminConsoleClient(context.Background(), appRepo, cfg.AdminConsoleClientID, splitCSV(cfg.AdminConsoleRedirectURIs)); err != nil {
		logger.Warnf("admin console client seeding skipped: %v", err)
	}
	dashboardHandler := handler.NewDashboardHandler(db, userRepo, appRepo, userAppRoleRepo)
	healthHandler := handler.NewHealthHandler(db)
	appLogsHandler := handler.NewAppLogsHandler(appActivityLogService)
	monitoringHandler := handler.NewMonitoringHandler(db, alertRuleRepo, triggeredAlertRepo, blockedIPRepo, securityAuditRepo, geoIPService)
	// So the audit-integrity endpoint reports "not_scanning" rather than
	// "verified" when the background scanner is disabled (F8).
	monitoringHandler.SetAuditScanningEnabled(cfg.AuditIntegrityScanInterval > 0)
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
	logger.Debug("✅ Web handler initialized")

	// ==========================================
	// Auto-Defense System (automatic IP blocking)
	// ==========================================
	autoDefense := service.NewAutoDefenseService(
		blockedIPRepo,
		securityAuditRepo,
		service.DefaultAutoDefenseConfig(),
	)
	logger.Debug("✅ Auto-defense system initialized")

	// IP Block Checker (middleware cache)
	ipBlockChecker := middleware.NewIPBlockChecker(
		blockedIPRepo,
		middleware.DefaultIPBlockCheckerConfig(),
	)
	logger.Debug("✅ IP block checker initialized")

	// Connect auto-defense to IP block checker for immediate cache invalidation
	autoDefense.SetOnBlockCallback(func(ip string) {
		ipBlockChecker.InvalidateCache()
	})

	// Wire auto-defense to auth handlers
	authHandler.SetAutoDefenseService(autoDefense)
	adminAuthHandler.SetAutoDefenseService(autoDefense)
	oauthHandler.SetAutoDefenseService(autoDefense) // P3-5: hosted login form

	// ==========================================
	// Rate Limiters (with graceful shutdown support)
	// ==========================================
	// B4: with STATE_BACKEND=postgres the counters live in the database, so N
	// instances share one budget instead of each enforcing the limit
	// independently (which would make the effective limit N times the
	// configured one). Memory is the default and behaves exactly as before.
	var rateLimitStore state.RateLimitStore
	var replayStore *state.PostgresReplayStore
	var stateSweepStop func()
	if cfg.StateBackend == state.BackendPostgres {
		pgLimits := state.NewPostgresRateLimitStore(db, cfg.StateOpTimeout)
		rateLimitStore = pgLimits
		replayStore = state.NewPostgresReplayStore(db, cfg.StateOpTimeout)
		sweeper := state.NewSweeper(cfg.StateSweepInterval, pgLimits, replayStore)
		stateSweepStop = cluster.Every(jobDB, cluster.LockStateSweep, "shared_state_sweep",
			cfg.StateSweepInterval, func(ctx context.Context) error {
				sweeper.SweepOnce(ctx)
				return nil
			})
		logger.WithFields(logger.Fields{
			"backend":        cfg.StateBackend,
			"sweep_interval": cfg.StateSweepInterval.String(),
			"op_timeout":     cfg.StateOpTimeout.String(),
		}).Info("B4: shared state enabled — rate limits and DPoP replay are cluster-wide")
	}

	// ==========================================
	// Policy decision point (A4)
	// ==========================================
	// The store and the policy API are always available, so an operator can
	// author and simulate rules before turning anything on; POLICY_MODE only
	// decides whether the admin API consults them. Version 1 is seeded with a
	// baseline that restates the existing code gates as rules, which is what
	// makes shadow mode's divergence counter meaningful from the first request.
	pdp := policy.NewService(policy.NewPostgresStore(db), policy.Mode(cfg.PolicyMode), cfg.PolicyRefreshInterval)
	if seeded, err := pdp.EnsureBaseline(context.Background()); err != nil {
		// Not fatal: in shadow mode nothing depends on it, and in enforce
		// mode the admin API answers 503 policy_unavailable — except the
		// policy routes, from which the baseline can be restored.
		logger.WithFields(logger.Fields{"error": err.Error(), "mode": cfg.PolicyMode}).
			Error("A4: could not seed the baseline policy")
	} else if seeded {
		logger.Info("A4: seeded policy version 1 (baseline mirroring the admin API's code gates)")
	}
	var policyDecisionSweepStop func()
	if cfg.PolicyDecisionRetention > 0 {
		retention := cfg.PolicyDecisionRetention
		policyDecisionSweepStop = cluster.Every(jobDB, cluster.LockPolicyDecisionSweep, "policy_decision_sweep",
			time.Hour, func(ctx context.Context) error {
				n, err := pdp.SweepDecisions(ctx, retention)
				if err == nil && n > 0 {
					logger.WithFields(logger.Fields{"deleted": n}).Info("A4: swept expired policy decisions")
				}
				return err
			})
	}
	logger.WithFields(logger.Fields{
		"mode":             cfg.PolicyMode,
		"refresh_interval": cfg.PolicyRefreshInterval.String(),
		"retention":        cfg.PolicyDecisionRetention.String(),
	}).Info("A4: policy decision point configured")

	// B5: readiness reports the dependencies this instance needs to serve a
	// token, so a load balancer takes it out of rotation for a missing signing
	// key or an unreachable shared-state backend, not only for a dead database.
	var stateProbe handler.StateProbe
	if replayStore != nil {
		stateProbe = replayStore
	}
	healthHandler.SetProbes(keyManager, stateProbe)

	newLimiter := func(namespace string, limit int, window time.Duration) middleware.Limiter {
		if rateLimitStore != nil {
			return state.NewStoreLimiter(rateLimitStore, namespace, limit, window)
		}
		return middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
			Limit:           limit,
			Window:          window,
			MaxEntries:      cfg.RateLimitMaxEntries,
			CleanupInterval: time.Minute,
		})
	}

	loginRateLimiter := newLimiter("login", cfg.RateLimitLogin, cfg.RateLimitLoginWindow)
	signupRateLimiter := newLimiter("signup", cfg.RateLimitSignup, cfg.RateLimitSignupWindow)

	// MED-05: token endpoint rate limiter — nil when explicitly disabled
	// (RATE_LIMIT_TOKEN=0).  A nil limiter leaves the token endpoint unprotected;
	// the production Validate() warning fires in that case.
	var tokenRateLimiter middleware.Limiter
	if cfg.RateLimitToken > 0 {
		tokenRateLimiter = newLimiter("token", cfg.RateLimitToken, cfg.RateLimitTokenWindow)
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
	// DPoP (RFC 9449) observe-mode telemetry on the token endpoint. The replay
	// cache (and its janitor) is created only when DPoP is enabled.
	var dpopReplayCache *dpop.MemoryReplayCache
	var dpopCache dpop.ReplayCache
	if cfg.DPoPMode != "off" && cfg.DPoPMode != "" {
		if replayStore != nil {
			// B4: a proof replayed against another instance must be rejected
			// there too, so the jti has to be shared. This is the one piece of
			// state whose in-process copy is a security hole rather than a
			// performance detail.
			dpopCache = replayStore
		} else {
			dpopReplayCache = dpop.NewMemoryReplayCache(time.Minute)
			dpopCache = dpopReplayCache
		}
		logger.WithFields(logger.Fields{
			"mode":    cfg.DPoPMode,
			"backend": cfg.StateBackend,
		}).Info("DPoP enabled (observe-mode telemetry on /oauth/token)")
	}

	routerConfig := internalhttp.RouterConfig{
		AllowedOrigins:       parseAllowedOrigins(cfg.AllowedOrigins),
		LoginRateLimiter:     loginRateLimiter,
		SignupRateLimiter:    signupRateLimiter,
		TokenRateLimiter:     tokenRateLimiter, // MED-05: nil only when explicitly disabled
		IPBlockChecker:       ipBlockChecker,
		TrustedProxyCIDRs:    mustParseTrustedProxies(cfg.TrustedProxies),
		DPoPMode:             cfg.DPoPMode,
		DPoPHTUBase:          cfg.OAuthIssuer,
		AdminElevationMaxAge: cfg.AdminElevationMaxAge, // Tier-0 step-up freshness window
		ScopeEnforce:         cfg.AdminScopeMode == "enforce",
		// A3: the webhook admin API is registered whenever the handler is
		// present, so an operator can prepare subscriptions before flipping
		// WEBHOOKS_MODE=on.
		WebhookHandler: handler.NewWebhookHandler(webhookService, adminLogService),
		// A4: the PEP is a pass-through in POLICY_MODE=off; the policy API is
		// registered regardless, so rules can be prepared before shadowing.
		PolicyPEP:     middleware.NewPolicyPEP(pdp, cfg.AdminElevationMaxAge),
		PolicyHandler: handler.NewPolicyHandler(pdp, adminLogService),
		// A4 part 2: applications consult the same PDP. Registered in every
		// mode; the response carries the mode, which is how an application's
		// enforcement point knows whether to act on the answer.
		PolicyDecideHandler: handler.NewPolicyDecideHandler(pdp, tokenService, userRepo, usedTokenRepo, userAppRoleRepo),
	}
	if geoIPService != nil && geoIPService.IsConfigured() {
		geo := geoIPService
		countryOf := func(ip string) string {
			if r := geo.Lookup(ip); r != nil && r.IsValid {
				return r.CountryCode
			}
			return ""
		}
		routerConfig.PolicyPEP.SetCountryLookup(countryOf)
		routerConfig.PolicyDecideHandler.SetCountryLookup(countryOf)
	}
	if dpopCache != nil {
		routerConfig.DPoPReplayCache = dpopCache
	}
	// Record a dpop_validation_failed security event on every rejected proof so
	// DPoP abuse / misconfiguration is visible to the monitoring console (#202).
	if cfg.DPoPMode == "observe" || cfg.DPoPMode == "enforce" {
		repo := securityAuditRepo
		routerConfig.DPoPRejectSink = func(r *http.Request, reason string, blocked bool) {
			_ = repo.Create(context.Background(), &model.SecurityAuditLog{
				EventType:     model.SecurityEventDPoPValidationFailed,
				Severity:      model.SecuritySeverityWarning,
				IPAddress:     middleware.GetClientIP(r),
				UserAgent:     r.UserAgent(),
				CorrelationID: middleware.GetCorrelationID(r.Context()),
				Success:       false,
				Details:       map[string]interface{}{"reason": reason, "blocked": blocked, "path": r.URL.Path},
				CreatedAt:     time.Now(),
			})
		}
	}

	// Record a token-abuse security event whenever a present bearer token is
	// rejected at a protected endpoint (#203). Invalid (forgery / malformed /
	// unknown-user) and revoked (nuclear or per-JTI) tokens are high-signal and
	// recorded; expired tokens are intentionally NOT recorded — a client hitting
	// expiry then refreshing is normal behaviour and would flood the console.
	{
		repo := securityAuditRepo
		routerConfig.AuthRejectSink = func(r *http.Request, reason middleware.AuthRejectReason, detail string) {
			var eventType model.SecurityEventType
			switch reason {
			case middleware.AuthRejectRevoked:
				eventType = model.SecurityEventRevokedTokenUsed
			case middleware.AuthRejectInvalid:
				eventType = model.SecurityEventInvalidTokenUsed
			default:
				// AuthRejectExpired (and any future reason) — not audited here.
				return
			}
			_ = repo.Create(context.Background(), &model.SecurityAuditLog{
				EventType:     eventType,
				Severity:      model.GetSeverityForEvent(eventType, false),
				IPAddress:     middleware.GetClientIP(r),
				UserAgent:     r.UserAgent(),
				CorrelationID: middleware.GetCorrelationID(r.Context()),
				Success:       false,
				Details:       map[string]interface{}{"reason": detail, "path": r.URL.Path},
				CreatedAt:     time.Now(),
			})
		}
	}

	// M-03: the admin API accepts only tokens issued to the operator consoles,
	// or minted by Socrate itself for it (admin-portal). A mismatch is audited
	// as admin_api_audience (observe: allowed; enforce: refused).
	{
		repo := securityAuditRepo
		accepted := append(cfg.ConsoleClientIDs(), service.AdminPortalClientID)
		routerConfig.AdminAudience = middleware.RequireAdminAudience(cfg.AdminAPIAudienceMode, accepted,
			func(r *http.Request, clientID string, refused bool) {
				var userID *uint
				if id, ok := middleware.GetUserIDFromContext(r.Context()); ok {
					userID = &id
				}
				eventType := model.SecurityEventAdminAPIAudience
				_ = repo.Create(context.Background(), &model.SecurityAuditLog{
					EventType:     eventType,
					Severity:      model.GetSeverityForEvent(eventType, !refused),
					UserID:        userID,
					IPAddress:     middleware.GetClientIP(r),
					UserAgent:     r.UserAgent(),
					CorrelationID: middleware.GetCorrelationID(r.Context()),
					Success:       !refused,
					Details: map[string]interface{}{
						"client_id": clientID, "path": r.URL.Path, "method": r.Method,
						"mode": cfg.AdminAPIAudienceMode,
					},
					CreatedAt: time.Now(),
				})
			})
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
			mfaHandler,
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
			usedTokenRepo, // EPIC-14: per-token revocation propagation
			userAppRoleRepo,
			appRepo,
			routerConfig,
		)
		return &App{
			OAuthRouter:          routers.OAuth,
			AdminRouter:          routers.Admin,
			DB:                   db,
			codeStore:            codeStore,
			loginRateLimiter:     loginRateLimiter,
			signupRateLimiter:    signupRateLimiter,
			tokenRateLimiter:     tokenRateLimiter, // MED-05
			autoDefense:          autoDefense,
			ipBlockChecker:       ipBlockChecker,
			keyRotationStop:      keyRotationStop,
			auditIntegrityStop:   auditIntegrityStop,
			usedTokenCleanupStop: usedTokenCleanupStop,
			webhookCacheStop:     webhookCacheStop,
			webhookDispatchStop:  webhookDispatchStop,
			auditAsync:           auditAsync,
			stateSweepStop:       stateSweepStop,
			dpopReplayCache:      dpopReplayCache,

			policyDecisionSweepStop: policyDecisionSweepStop,
		}
	}

	// Single-port mode: combined router only.
	combinedRouter := internalhttp.NewRouter(
		authHandler,
		oauthHandler,
		appUsersHandler,
		profileHandler,
		mfaHandler,
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
		usedTokenRepo, // EPIC-14: per-token revocation propagation
		userAppRoleRepo,
		appRepo,
		routerConfig,
	)
	return &App{
		Router:               combinedRouter,
		DB:                   db,
		codeStore:            codeStore,
		loginRateLimiter:     loginRateLimiter,
		signupRateLimiter:    signupRateLimiter,
		tokenRateLimiter:     tokenRateLimiter, // MED-05
		autoDefense:          autoDefense,
		ipBlockChecker:       ipBlockChecker,
		keyRotationStop:      keyRotationStop,
		auditIntegrityStop:   auditIntegrityStop,
		usedTokenCleanupStop: usedTokenCleanupStop,
		webhookCacheStop:     webhookCacheStop,
		webhookDispatchStop:  webhookDispatchStop,
		auditAsync:           auditAsync,
		stateSweepStop:       stateSweepStop,
		dpopReplayCache:      dpopReplayCache,

		policyDecisionSweepStop: policyDecisionSweepStop,
	}
}
