package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/state"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// Config holds all application configuration
type Config struct {
	// Server
	Port      string
	AdminPort string // Separate port for admin API (set to "" to disable)
	// AdminBindHost is the interface the admin API binds to. Defaults to
	// 127.0.0.1 (loopback) so the Tier-0 control plane is unreachable from the
	// public internet without relying on an external firewall — a reverse proxy
	// (Caddy) or BFF on the same host fronts it. Set to "0.0.0.0" (or "") only
	// for multi-host/container deployments that reach the admin API across the
	// network and enforce isolation by network policy instead.
	AdminBindHost string
	Host          string
	Environment   string

	// AdminConsoleClientID is the client_id of the first-party admin console — a
	// public, PKCE client. When non-empty, the token endpoint delivers that
	// client's refresh token as an HttpOnly; Secure; SameSite=Strict cookie
	// (XSS-safe silent refresh) instead of in the JSON body, and logout clears
	// it. Empty (default) disables the cookie channel entirely. Tier-0 admin
	// session hardening.
	AdminConsoleClientID string

	// AdminScopeMode gates least-privilege OAuth-scope enforcement on the admin
	// API (#201): "off" (default — admin routes are role-gated only, unchanged)
	// or "enforce" (routes additionally require monitoring:read/write or the
	// admin super-scope, confining a least-privilege client such as the
	// monitoring BFF to its routes). Enable only after registering each console's
	// client with the right scopes. ADMIN_SCOPE_MODE.
	AdminScopeMode string

	// AdminElevationMaxAge is the freshness window for admin step-up: the most
	// destructive admin routes (delete client, rotate secret, create/delete
	// superadmin, block user) require an authentication (auth_time) within this
	// window. Default 5 min; 0 disables the gate.
	AdminElevationMaxAge time.Duration

	// AdminConsoleRedirectURIs are the exact-match redirect URIs registered for
	// the first-party admin-console public PKCE client. When set together with
	// AdminConsoleClientID, that client is seeded at startup (public, PKCE
	// mandatory, no secret). Comma-separated; empty skips seeding.
	AdminConsoleRedirectURIs string

	// AdminPasswordLoginEnabled gates the legacy /api/admin/login password flow.
	// Default true (backward compatible); set false once the admin console is on
	// Authorization Code + PKCE so the deprecated password endpoint is refused.
	AdminPasswordLoginEnabled bool

	// Database
	DatabaseURL string
	DBPoolSize  int
	DBTimeout   time.Duration
	// DBLogLevel controls GORM query logging: silent | error | warn | info.
	// Default warn — normal queries are not logged (avoids bound-parameter
	// secrets/PII at info, HIGH-06); only slow queries and errors are. info
	// surfaces every statement at DEBUG (needs LOG_LEVEL=debug too).
	DBLogLevel string

	// JWT
	// M-10 fix: JWTSecret was loaded from JWT_SECRET but never used — the
	// server signs all tokens with RSA keys managed by KeyManager, not with
	// a symmetric secret.  Removed to avoid misleading operators into thinking
	// setting JWT_SECRET has any effect on token security.
	OAuthIssuer string

	// Token TTLs
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	EmailTokenTTL   time.Duration
	ResetTokenTTL   time.Duration
	InviteTokenTTL  time.Duration
	// JWKSCacheMaxAge is the Cache-Control max-age advertised on the JWKS
	// endpoint so resource servers cache the key set instead of refetching on
	// every token verification. Kept modest so a rotated key is picked up
	// promptly (a resource server should also refetch on an unknown kid). 0
	// disables caching (Cache-Control: no-store). RFC-002.
	JWKSCacheMaxAge time.Duration

	// Security
	MaxFailedAttempts   int
	LockoutDurationSecs int
	// AdminMFAPolicy governs whether a Socrate admin or superadmin must have MFA
	// enrolled to sign in, on every login path (the hosted login included):
	// "off" (default, unchanged behaviour), "observe" (allow but audit admins
	// without MFA), or "enforce" (deny until the admin enrolls). RFC-011.
	AdminMFAPolicy string
	// AdminAppSignInPolicy governs whether a Socrate admin or superadmin may sign
	// in to an application that is not an operator console: "off" (default,
	// unchanged — an admin is the implicit admin of any app), "observe" (allow
	// but audit admin_app_signin), or "enforce" (refuse at /oauth/authorize and
	// on refresh). ADMIN_APP_SIGNIN_POLICY.
	AdminAppSignInPolicy string
	// OperatorConsoleClientIDs lists, comma-separated, the client_ids of the
	// operator consoles (admin and monitoring BFFs), where an admin keeps
	// signing in under every AdminAppSignInPolicy mode. AdminConsoleClientID is
	// always included. OPERATOR_CONSOLE_CLIENT_IDS.
	OperatorConsoleClientIDs string
	// AuditWriteMode is how security audit rows are written: "sync" (default —
	// inside the request, as before) or "async" (queued and appended in batches
	// by a background writer, so a token request no longer waits on the audit
	// chain lock and its commit; rows still queued at a crash are lost).
	// AUDIT_WRITE_MODE.
	AuditWriteMode string
	// DPoPMode controls DPoP (RFC 9449) sender-constraint handling at the token
	// endpoint: "off" (default), "observe" (verify any DPoP proof, log telemetry,
	// and bind the issued token when a valid proof is sent, but never reject), or
	// "enforce" (same as observe, but a proof that is present and invalid is
	// rejected with 400 invalid_dpop_proof; a request with no proof still
	// proceeds). RFC-003.
	DPoPMode string
	// TokenExchangeMode controls OAuth 2.0 Token Exchange (RFC 8693): "off"
	// (default — the grant is unsupported), "shadow" (validate + audit attempts
	// but never issue an exchanged token), or "enforce" (validate, audit, and
	// actually issue the exchanged token). RFC-019.
	TokenExchangeMode string
	// ImpersonationTokenTTL time-boxes access tokens minted via impersonation
	// (the actor-absent token-exchange case, EPIC-17). Impersonation is
	// sensitive, so its tokens auto-expire quickly and are never longer-lived
	// than a normal access token (the value is capped at AccessTokenTTL at
	// issuance). Configured via IMPERSONATION_TOKEN_TTL (seconds); defaults to
	// 300s (5 minutes). Delegation is unaffected. RFC-016.
	ImpersonationTokenTTL time.Duration
	// ImpersonationStepUpMode governs the impersonation step-up check (EPIC-17):
	// "off" (default — no check), "observe" (audit a would-be denial but still
	// issue), or "enforce" (deny when the subject's authentication is older than
	// ImpersonationMaxAuthAge). There is no interactive user in the back-channel
	// token-exchange flow, so freshness of the impersonated subject's session is
	// the step-up control. RFC-016.
	ImpersonationStepUpMode string
	// ImpersonationMaxAuthAge is the freshness window for the step-up check
	// (IMPERSONATION_MAX_AUTH_AGE seconds; default 900s / 15 min). Zero disables
	// the check regardless of mode.
	ImpersonationMaxAuthAge time.Duration
	// DelegationStepUpMode governs the delegation step-up check (EPIC-17): "off"
	// (default — no check), "observe" (audit a would-be denial but still issue),
	// or "enforce" (deny when the actor token does not evidence MFA, i.e. its
	// `amr` does not contain "mfa"). Unlike impersonation, delegation carries an
	// actor token whose `amr` shows how the human actor authenticated. RFC-016.
	DelegationStepUpMode string
	// RefreshReuseMode governs refresh-token reuse detection (OAuth 2.0 Security
	// BCP / RFC 9700 §4.14.2): "off" (default — a reused single-use refresh token
	// is rejected, unchanged), "observe" (also audit the reuse), or "enforce"
	// (also revoke the user's token family, since reuse signals token theft).
	RefreshReuseMode string
	// ScopePolicyMode governs the per-client allowed_scopes policy (A1 / P3-8):
	// "off" (default — policy stored but not applied), "observe" (audit
	// scope_denied, still issue), "enforce" (refuse with invalid_scope).
	ScopePolicyMode string
	// AudienceMode controls how an access token's `aud` is built from the client
	// and its registered audiences (RFC-001 / EPIC-7): "off" (default — aud is
	// the client_id, unchanged) or "dual" (the client's registered audiences are
	// added alongside the client_id, so audience-aware resource servers can begin
	// verifying their resource identifier while client_id verifiers keep working).
	// Canonical-only enforcement is a later (Wave 2) step. AUDIENCE_MODE.
	AudienceMode string
	// ClaimsNamespace prefixes every custom claim a client's claim-mapping
	// policy projects into its tokens (A2). Namespacing is what keeps a mapping
	// from shadowing a registered or standard claim: a mapping named `role`
	// becomes `https://socrate/role`. CLAIMS_NAMESPACE; defaults to
	// auth.DefaultClaimsNamespace.
	ClaimsNamespace string
	// WebhooksEnabled turns on the A3 outbox: audited events in the webhook
	// catalogue are enqueued for every matching subscription, in the same
	// transaction as the audit row. Default false — with it off, subscriptions
	// can still be managed but nothing is enqueued or delivered. WEBHOOKS_MODE
	// ("off" default | "on").
	WebhooksEnabled bool
	// WebhookCacheRefresh is how often each instance reloads its webhook
	// subscription routing cache, which is what bounds how long another
	// instance's change takes to take effect here. WEBHOOK_CACHE_REFRESH.
	WebhookCacheRefresh time.Duration
	// Webhook dispatcher tuning (A3 part 2). WEBHOOK_MAX_ATTEMPTS bounds retries
	// before a delivery is dead-lettered; WEBHOOK_POLL_INTERVAL is how often the
	// outbox is drained; WEBHOOK_BATCH_SIZE is how many rows one pass claims;
	// WEBHOOK_SEND_TIMEOUT bounds a single attempt.
	WebhookMaxAttempts  int
	WebhookPollInterval time.Duration
	WebhookBatchSize    int
	WebhookSendTimeout  time.Duration
	// StateBackend selects where the shared security state lives (B4):
	// "memory" (default — correct for one instance) or "postgres" (correct
	// under N instances, using the database already configured). Rate-limit
	// counters and the DPoP replay cache follow this setting.
	StateBackend string
	// StateSweepInterval is how often expired shared-state rows are evicted.
	// The stores are correct without it — every read filters on expiry — so
	// this only bounds table growth.
	StateSweepInterval time.Duration
	// StateOpTimeout bounds a single shared-state round trip, so a slow
	// database degrades the limiter rather than the request path.
	StateOpTimeout time.Duration
	// PolicyMode is the A4 rollout switch, POLICY_MODE: "off" (default — the
	// policy API works but nothing is consulted), "shadow" (every admin
	// request is evaluated and compared with the code gates, nothing is
	// refused), or "enforce" (a policy deny is refused with 403; an allow
	// still has to pass every code gate).
	PolicyMode string
	// PolicyRefreshInterval bounds how long another instance's policy save
	// takes to be seen here. POLICY_REFRESH_INTERVAL (seconds, default 10).
	PolicyRefreshInterval time.Duration
	// PolicyDecisionRetention is how long decision-log rows are kept.
	// POLICY_DECISION_RETENTION_DAYS (default 30).
	PolicyDecisionRetention time.Duration
	// SecretKeyBase is a cryptographic secret (≥32 bytes in production) used
	// for two purposes:
	//   1. CSRF cookie signing in the OAuth authorization handler (CRIT-03):
	//      the value is passed as secretKey to handler.NewOAuthHandler, which
	//      uses it to HMAC-sign consent tokens so they cannot be forged.
	//   2. Consent token integrity (CRIT-04): the same key protects the
	//      opaque consent token embedded in the authorization form.
	// LOW-01 fix: this field is documented and wired — it is NOT unused.
	// Operators must set SECRET_KEY_BASE to a random ≥32-byte value in
	// production (enforced by Validate()).
	SecretKeyBase string

	// Rate Limiting
	RateLimitLogin        int
	RateLimitLoginWindow  time.Duration
	RateLimitSignup       int
	RateLimitSignupWindow time.Duration
	// MED-05: RateLimitToken / RateLimitTokenWindow control the per-IP
	// rate limiter applied to POST /oauth/token.  A value of 0 disables
	// the limiter (not recommended for production).  Defaults to 10
	// requests per 60 seconds, which allows normal token refresh cadences
	// while blocking brute-force attacks on authorization codes and client
	// credentials.  Configured via RATE_LIMIT_TOKEN and
	// RATE_LIMIT_TOKEN_WINDOW_MS (or legacy RATE_LIMIT_TOKEN_WINDOW).
	RateLimitToken       int
	RateLimitTokenWindow time.Duration
	RateLimitMaxEntries  int

	// Email/SMTP
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPSecurity string
	FromEmail    string
	FromName     string

	// Keys
	KeysPath string

	// KeyRotationInterval is how often the signing key is automatically rotated.
	// Zero (the default) disables scheduled rotation — keys then rotate only on
	// explicit operator action (KEY_ROTATION_INTERVAL_SECONDS).
	KeyRotationInterval time.Duration
	// KeyRetention is how long a retired signing key is kept (for verifying
	// outstanding tokens) before it is pruned from the ring and JWKS. Zero (the
	// default) means "derive from RefreshTokenTTL" so retired keys always
	// outlive the longest token (KEY_RETENTION_SECONDS).
	KeyRetention time.Duration

	// AuditIntegrityScanInterval is how often the audit-row integrity scan runs.
	// Zero (the default) disables it (AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS).
	AuditIntegrityScanInterval time.Duration
	// AuditIntegrityScanLookback is the trailing window each scan verifies.
	// Defaults to 24h (AUDIT_INTEGRITY_SCAN_LOOKBACK_SECONDS).
	AuditIntegrityScanLookback time.Duration

	// UsedTokenCleanupInterval is how often expired rows are pruned from the
	// used_tokens table (single-use refresh JTIs + the per-token revocation
	// blacklist). Without pruning the table grows without bound. Defaults to 1h;
	// 0 disables the scheduled cleanup (USED_TOKEN_CLEANUP_INTERVAL_SECONDS).
	// EPIC-14 / RFC-012.
	UsedTokenCleanupInterval time.Duration

	// Trusted Proxies
	// Comma-separated IPs or CIDR ranges whose X-Forwarded-For / X-Real-IP
	// headers are trusted for real-IP extraction (e.g. "10.0.0.0/8,172.16.0.0/12").
	// Defaults to loopback ("127.0.0.1/32,::1/128"): the documented topology
	// fronts both listeners with a same-host Caddy / BFF, and the admin API is
	// loopback-bound, so every peer it sees IS the proxy — without trusting it,
	// rate limits, IP blocks and audit attribution collapse onto 127.0.0.1.
	// Internet peers never connect from loopback, so the default is inert when
	// the server is exposed directly. Set to "none" to trust no proxy at all.
	TrustedProxies string

	// CORS
	// Comma-separated list of allowed origins (e.g. "https://app.example.com,https://admin.example.com").
	// H-06 fix: when empty the server uses a wildcard without AllowCredentials.
	// Setting explicit origins enables AllowCredentials for those origins only.
	AllowedOrigins string

	// GeoIP
	GeoIPCityDBPath string // Path to GeoLite2-City.mmdb
	GeoIPASNDBPath  string // Path to GeoLite2-ASN.mmdb (optional)

	// Migrations
	// M-01 fix: AutoMigrate runs GORM's schema diffing on every startup, which
	// can silently add columns or indexes in production.  Set AUTO_MIGRATE=true
	// only during initial deployment or when intentionally rolling out a schema
	// change.  Default is false so production restarts never touch the schema.
	AutoMigrate bool
}

// Load loads configuration from environment variables
func Load() *Config {
	// Load .env file (ignore error in production)
	_ = godotenv.Load()

	cfg := &Config{
		// Server
		Port:          getEnv("PORT", "8080"),
		AdminPort:     getEnv("ADMIN_PORT", ""),               // Empty = disabled (use single port mode)
		AdminBindHost: getEnv("ADMIN_BIND_HOST", "127.0.0.1"), // Loopback by default — internal-only Tier-0 control plane
		Host:          getEnv("PHX_HOST", "localhost"),
		// MED-04 fix: default to "production" so that a server accidentally
		// started without an ENV variable does not silently operate in an
		// insecure mode (e.g. leaking email verification tokens in API
		// responses per MED-03, or skipping SecretKeyBase validation).
		// Operators must explicitly set ENV=development or ENV=test to opt
		// into a less-restrictive mode.
		Environment: getEnv("ENV", "production"),

		// Tier-0 admin session hardening: empty disables the cookie channel.
		AdminConsoleClientID: getEnv("ADMIN_CONSOLE_CLIENT_ID", ""),

		// Freshness window for admin step-up: the most destructive admin routes
		// require an authentication (auth_time) no older than this. Default 300s
		// (5 min); 0 disables the gate.
		AdminScopeMode:       getEnv("ADMIN_SCOPE_MODE", "off"),
		AdminElevationMaxAge: time.Duration(getEnvInt("ADMIN_ELEVATION_MAX_AGE", 300)) * time.Second,

		AdminConsoleRedirectURIs:  getEnv("ADMIN_CONSOLE_REDIRECT_URIS", ""),
		AdminPasswordLoginEnabled: getEnvBool("ADMIN_PASSWORD_LOGIN_ENABLED", true),

		// Database
		DatabaseURL: getEnv("DATABASE_URL", "postgres://localhost/socrate_auth_dev"),
		DBPoolSize:  getEnvInt("DB_POOL_SIZE", 10),
		DBTimeout:   time.Duration(getEnvInt("DB_TIMEOUT_SECONDS", 30)) * time.Second,
		DBLogLevel:  getEnv("DB_LOG_LEVEL", "warn"),

		// JWT
		OAuthIssuer: getEnv("OAUTH_ISSUER", "http://localhost:8080"),

		// Token TTLs
		AccessTokenTTL:  time.Duration(getEnvInt("ACCESS_TOKEN_TTL", 900)) * time.Second,
		RefreshTokenTTL: time.Duration(getEnvInt("REFRESH_TOKEN_TTL", 604800)) * time.Second,
		EmailTokenTTL:   time.Duration(getEnvInt("EMAIL_TOKEN_TTL", 86400)) * time.Second,
		ResetTokenTTL:   time.Duration(getEnvInt("RESET_TOKEN_TTL", 3600)) * time.Second,
		JWKSCacheMaxAge: time.Duration(getEnvInt("JWKS_CACHE_MAX_AGE_SECONDS", 300)) * time.Second,
		InviteTokenTTL:  time.Duration(getEnvInt("INVITE_TOKEN_TTL", 86400)) * time.Second,

		// Security
		MaxFailedAttempts:        getEnvInt("MAX_FAILED_ATTEMPTS", 5),
		LockoutDurationSecs:      getEnvInt("LOCKOUT_DURATION_SECONDS", 900),
		SecretKeyBase:            getEnv("SECRET_KEY_BASE", ""),
		AdminMFAPolicy:           normalizeAdminMFAPolicy(getEnv("ADMIN_MFA_POLICY", "off")),
		AdminAppSignInPolicy:     normalizeStepUpMode(getEnv("ADMIN_APP_SIGNIN_POLICY", "off")),
		OperatorConsoleClientIDs: getEnv("OPERATOR_CONSOLE_CLIENT_IDS", ""),
		AuditWriteMode:           normalizeAuditWriteMode(getEnv("AUDIT_WRITE_MODE", "sync")),
		DPoPMode:                 normalizeDPoPMode(getEnv("DPOP_MODE", "off")),
		TokenExchangeMode:        normalizeTokenExchangeMode(getEnv("TOKEN_EXCHANGE_MODE", "off")),
		ImpersonationTokenTTL:    time.Duration(getEnvInt("IMPERSONATION_TOKEN_TTL", 300)) * time.Second,
		ImpersonationStepUpMode:  normalizeStepUpMode(getEnv("IMPERSONATION_STEPUP_MODE", "off")),
		ImpersonationMaxAuthAge:  time.Duration(getEnvInt("IMPERSONATION_MAX_AUTH_AGE", 900)) * time.Second,
		DelegationStepUpMode:     normalizeStepUpMode(getEnv("DELEGATION_STEPUP_MODE", "off")),
		RefreshReuseMode:         normalizeStepUpMode(getEnv("REFRESH_REUSE_MODE", "off")),
		ScopePolicyMode:          normalizeStepUpMode(getEnv("SCOPE_POLICY_MODE", "off")),
		AudienceMode:             normalizeAudienceMode(getEnv("AUDIENCE_MODE", "off")),
		ClaimsNamespace:          getEnv("CLAIMS_NAMESPACE", ""),
		WebhooksEnabled:          strings.EqualFold(strings.TrimSpace(getEnv("WEBHOOKS_MODE", "off")), "on"),
		WebhookCacheRefresh:      time.Duration(getEnvInt("WEBHOOK_CACHE_REFRESH", 60)) * time.Second,
		WebhookMaxAttempts:       getEnvInt("WEBHOOK_MAX_ATTEMPTS", 6),
		WebhookPollInterval:      time.Duration(getEnvInt("WEBHOOK_POLL_INTERVAL", 10)) * time.Second,
		WebhookBatchSize:         getEnvInt("WEBHOOK_BATCH_SIZE", 20),
		WebhookSendTimeout:       time.Duration(getEnvInt("WEBHOOK_SEND_TIMEOUT", 5)) * time.Second,
		StateBackend:             state.NormalizeBackend(getEnv("STATE_BACKEND", "memory")),
		StateSweepInterval:       time.Duration(getEnvInt("STATE_SWEEP_INTERVAL", 300)) * time.Second,
		StateOpTimeout:           time.Duration(getEnvInt("STATE_OP_TIMEOUT_MS", 2000)) * time.Millisecond,
		PolicyMode:               string(policy.NormalizeMode(getEnv("POLICY_MODE", "off"))),
		PolicyRefreshInterval:    time.Duration(getEnvInt("POLICY_REFRESH_INTERVAL", 10)) * time.Second,
		PolicyDecisionRetention:  time.Duration(getEnvInt("POLICY_DECISION_RETENTION_DAYS", 30)) * 24 * time.Hour,

		// Rate Limiting
		// LOW-03 fix: window env vars now have an explicit _MS suffix so
		// operators know the unit is milliseconds.  The old names without the
		// suffix are still accepted as a backwards-compatible fallback.
		// Default 60000 ms = 60 s for login; 3600000 ms = 60 min for signup.
		RateLimitLogin: getEnvInt("RATE_LIMIT_LOGIN", 5),
		RateLimitLoginWindow: time.Duration(
			getEnvIntFallback("RATE_LIMIT_LOGIN_WINDOW_MS", "RATE_LIMIT_LOGIN_WINDOW", 60000),
		) * time.Millisecond,
		RateLimitSignup: getEnvInt("RATE_LIMIT_SIGNUP", 3),
		RateLimitSignupWindow: time.Duration(
			getEnvIntFallback("RATE_LIMIT_SIGNUP_WINDOW_MS", "RATE_LIMIT_SIGNUP_WINDOW", 3600000),
		) * time.Millisecond,
		// MED-05: token endpoint rate limiting.  10 requests per 60 s is
		// sufficient for legitimate OAuth clients (a user refreshing every
		// minute generates 1 req/min) while blocking fast brute-force probes.
		// Set RATE_LIMIT_TOKEN=0 to explicitly disable (not recommended).
		RateLimitToken: getEnvInt("RATE_LIMIT_TOKEN", 10),
		RateLimitTokenWindow: time.Duration(
			getEnvIntFallback("RATE_LIMIT_TOKEN_WINDOW_MS", "RATE_LIMIT_TOKEN_WINDOW", 60000),
		) * time.Millisecond,
		RateLimitMaxEntries: getEnvInt("RATE_LIMIT_MAX_ENTRIES", 10000),

		// Email/SMTP
		SMTPHost:     getEnv("SMTP_HOST", ""),
		SMTPPort:     getEnvInt("SMTP_PORT", 587),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPSecurity: getEnv("SMTP_SECURITY", "starttls"),
		FromEmail:    getEnv("FROM_EMAIL", "no-reply@example.com"),
		FromName:     getEnv("FROM_NAME", "Socrate"),

		// Keys
		KeysPath: getEnv("KEYS_PATH", "keys"),
		// 0 = disabled (manual rotation only).
		KeyRotationInterval: time.Duration(getEnvInt("KEY_ROTATION_INTERVAL_SECONDS", 0)) * time.Second,
		// 0 = derive from RefreshTokenTTL at bootstrap.
		KeyRetention: time.Duration(getEnvInt("KEY_RETENTION_SECONDS", 0)) * time.Second,
		// 0 = disabled; lookback defaults to 24h.
		AuditIntegrityScanInterval: time.Duration(getEnvInt("AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS", 0)) * time.Second,
		AuditIntegrityScanLookback: time.Duration(getEnvInt("AUDIT_INTEGRITY_SCAN_LOOKBACK_SECONDS", 86400)) * time.Second,
		UsedTokenCleanupInterval:   time.Duration(getEnvInt("USED_TOKEN_CLEANUP_INTERVAL_SECONDS", 3600)) * time.Second,

		// Trusted Proxies
		TrustedProxies: getEnv("TRUSTED_PROXIES", "127.0.0.1/32,::1/128"),

		// CORS
		AllowedOrigins: getEnv("ALLOWED_ORIGINS", ""),

		// GeoIP
		GeoIPCityDBPath: getEnv("GEOIP_CITY_DB", ""),
		GeoIPASNDBPath:  getEnv("GEOIP_ASN_DB", ""),

		// Migrations
		AutoMigrate: getEnvBool("AUTO_MIGRATE", false),
	}

	return cfg
}

// Validate validates the configuration for the given environment
// Returns an error if required configuration is missing in production
func (c *Config) Validate() error {
	// Every environment: enforce with no console listed would lock every
	// operator out of the consoles. Refuse to start instead.
	if c.AdminAppSignInPolicy == "enforce" && len(c.ConsoleClientIDs()) == 0 {
		return fmt.Errorf("ADMIN_APP_SIGNIN_POLICY=enforce needs OPERATOR_CONSOLE_CLIENT_IDS (or ADMIN_CONSOLE_CLIENT_ID): without a console, no admin could sign in")
	}
	if c.IsProduction() {
		// Critical security settings that must be set in production
		if c.SecretKeyBase == "" {
			return fmt.Errorf("SECRET_KEY_BASE must be set in production")
		}
		if len(c.SecretKeyBase) < 32 {
			return fmt.Errorf("SECRET_KEY_BASE must be at least 32 characters in production")
		}
		if c.DatabaseURL == "" || c.DatabaseURL == "postgres://localhost/socrate_auth_dev" {
			return fmt.Errorf("DATABASE_URL must be set to a production database")
		}
		if c.OAuthIssuer == "" || c.OAuthIssuer == "http://localhost:8080" {
			return fmt.Errorf("OAUTH_ISSUER must be set to a production URL")
		}
		// L4 fix: httpsRequired (redirect-URI HTTPS enforcement) and the
		// Secure flag on CSRF/consent/refresh cookies are all derived from
		// strings.HasPrefix(issuer, "https://") — see handler.NewOAuthHandler
		// and cmd/server/bootstrap.go. An http:// issuer in production would
		// silently disable both, so require https:// explicitly here.
		if !strings.HasPrefix(c.OAuthIssuer, "https://") {
			return fmt.Errorf("OAUTH_ISSUER must use https:// in production (got %q)", c.OAuthIssuer)
		}
		// L-05 fix: a relative KEYS_PATH resolves against the working directory
		// at startup time.  If the server is started from a different directory
		// (e.g. via systemd with WorkingDirectory=/), the relative path silently
		// generates a brand-new key pair, invalidating all outstanding tokens.
		// Require an absolute path in production so the key location is
		// unambiguous regardless of how the process is launched.
		if !filepath.IsAbs(c.KeysPath) {
			return fmt.Errorf("KEYS_PATH must be an absolute path in production (currently %q); set KEYS_PATH to an absolute directory", c.KeysPath)
		}
		// MED-07 fix: use the structured logger instead of fmt.Println so this
		// warning appears in centralized log aggregation (Datadog, Splunk, etc.)
		// and is not silently dropped in containerized environments where stdout
		// is not captured.
		if c.AccessTokenTTL > 30*time.Minute {
			logger.WithFields(logger.Fields{
				"access_token_ttl_minutes": c.AccessTokenTTL.Minutes(),
				"recommended_max_minutes":  30,
			}).Warn("MED-07: ACCESS_TOKEN_TTL exceeds 30 minutes — consider reducing for better security")
		}
		// MED-05: warn loudly when the token endpoint rate limiter is disabled
		// in production.  Without it the token endpoint is vulnerable to
		// authorization-code brute-force, refresh-token scanning, and client
		// credential password-spraying.  Operators must set RATE_LIMIT_TOKEN=0
		// deliberately to reach this path.
		if c.RateLimitToken == 0 {
			logger.WithFields(logger.Fields{
				"endpoint":           "POST /oauth/token",
				"env_var":            "RATE_LIMIT_TOKEN",
				"recommended_limit":  10,
				"recommended_window": "60s",
			}).Warn("MED-05: token endpoint rate limiting is DISABLED — set RATE_LIMIT_TOKEN to enable brute-force protection")
		}
	}
	return nil
}

// ConsoleClientIDs returns the operator consoles' client_ids: those listed in
// OPERATOR_CONSOLE_CLIENT_IDS plus ADMIN_CONSOLE_CLIENT_ID, trimmed, without
// empty entries or duplicates.
func (c *Config) ConsoleClientIDs() []string {
	var ids []string
	seen := map[string]bool{}
	for _, id := range append(strings.Split(c.OperatorConsoleClientIDs, ","), c.AdminConsoleClientID) {
		if id = strings.TrimSpace(id); id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production" || c.Environment == "prod"
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development" || c.Environment == "dev"
}

// IsTest returns true if running in test environment
func (c *Config) IsTest() bool {
	return c.Environment == "test"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// normalizeTokenExchangeMode lower-cases and validates the token-exchange mode,
// falling back to "off" for any unrecognized value (fail safe — the sensitive
// grant is never enabled from a typo).
func normalizeTokenExchangeMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "shadow":
		return "shadow"
	case "enforce":
		return "enforce"
	default:
		return "off"
	}
}

// normalizeAudienceMode lower-cases and validates the audience-binding mode,
// falling back to "off" for any unrecognized value (fail safe — `aud` stays the
// client_id from a typo rather than changing token contents unexpectedly).
func normalizeAudienceMode(v string) string {
	if strings.ToLower(strings.TrimSpace(v)) == "dual" {
		return "dual"
	}
	return "off"
}

// normalizeAuditWriteMode returns "async" only for that value, else "sync"
// (a typo keeps the historical inline write).
func normalizeAuditWriteMode(v string) string {
	if strings.ToLower(strings.TrimSpace(v)) == "async" {
		return "async"
	}
	return "sync"
}

// normalizeStepUpMode lower-cases and validates the impersonation step-up mode,
// falling back to "off" for any unrecognized value (fail safe — never enforce
// or observe from a typo).
func normalizeStepUpMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "observe":
		return "observe"
	case "enforce":
		return "enforce"
	default:
		return "off"
	}
}

// normalizeDPoPMode lower-cases and validates the DPoP mode, falling back to
// "off" for any unrecognized value (fail safe — never enable an unintended
// mode from a typo).
func normalizeDPoPMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "observe":
		return "observe"
	case "enforce":
		return "enforce"
	default:
		return "off"
	}
}

// normalizeAdminMFAPolicy lower-cases and validates the admin MFA policy,
// falling back to "off" for any unrecognized value so a typo fails safe (open)
// rather than locking admins out.
func normalizeAdminMFAPolicy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "observe":
		return "observe"
	case "enforce":
		return "enforce"
	default:
		return "off"
	}
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

// getEnvIntFallback returns the integer value of the first env var that is
// set and parses successfully.  If neither is set the defaultValue is used.
// LOW-03: used to support both the new _MS-suffixed names and the old names.
func getEnvIntFallback(primary, fallback string, defaultValue int) int {
	if value := os.Getenv(primary); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	if value := os.Getenv(fallback); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}
