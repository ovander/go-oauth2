package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// Config holds all application configuration
type Config struct {
	// Server
	Port        string
	AdminPort   string // Separate port for admin API (set to "" to disable)
	Host        string
	Environment string

	// Database
	DatabaseURL string
	DBPoolSize  int
	DBTimeout   time.Duration

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
	// AdminMFAPolicy governs whether admin-portal login requires MFA enrollment:
	// "off" (default, unchanged behaviour), "observe" (allow but audit admins
	// without MFA), or "enforce" (deny until the admin enrolls). RFC-011.
	AdminMFAPolicy string
	// DPoPMode controls DPoP (RFC 9449) sender-constraint handling at the token
	// endpoint: "off" (default), "observe" (verify any DPoP proof and log
	// telemetry without affecting responses), or "enforce" (reserved for a later
	// slice; currently behaves as observe). RFC-003.
	DPoPMode string
	// TokenExchangeMode controls OAuth 2.0 Token Exchange (RFC 8693): "off"
	// (default — the grant is unsupported), "shadow" (validate + audit attempts
	// but never issue an exchanged token), or "enforce" (reserved; actually
	// issue). RFC-019.
	TokenExchangeMode string
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

	// Trusted Proxies
	// Comma-separated IPs or CIDR ranges whose X-Forwarded-For / X-Real-IP
	// headers are trusted for real-IP extraction (e.g. "10.0.0.0/8,172.16.0.0/12").
	// Leave empty when the server is exposed directly to the internet.
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
		Port:      getEnv("PORT", "8080"),
		AdminPort: getEnv("ADMIN_PORT", ""), // Empty = disabled (use single port mode)
		Host:      getEnv("PHX_HOST", "localhost"),
		// MED-04 fix: default to "production" so that a server accidentally
		// started without an ENV variable does not silently operate in an
		// insecure mode (e.g. leaking email verification tokens in API
		// responses per MED-03, or skipping SecretKeyBase validation).
		// Operators must explicitly set ENV=development or ENV=test to opt
		// into a less-restrictive mode.
		Environment: getEnv("ENV", "production"),

		// Database
		DatabaseURL: getEnv("DATABASE_URL", "postgres://localhost/socrate_auth_dev"),
		DBPoolSize:  getEnvInt("DB_POOL_SIZE", 10),
		DBTimeout:   time.Duration(getEnvInt("DB_TIMEOUT_SECONDS", 30)) * time.Second,

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
		MaxFailedAttempts:   getEnvInt("MAX_FAILED_ATTEMPTS", 5),
		LockoutDurationSecs: getEnvInt("LOCKOUT_DURATION_SECONDS", 900),
		SecretKeyBase:       getEnv("SECRET_KEY_BASE", ""),
		AdminMFAPolicy:      normalizeAdminMFAPolicy(getEnv("ADMIN_MFA_POLICY", "off")),
		DPoPMode:            normalizeDPoPMode(getEnv("DPOP_MODE", "off")),
		TokenExchangeMode:   normalizeTokenExchangeMode(getEnv("TOKEN_EXCHANGE_MODE", "off")),

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

		// Trusted Proxies
		TrustedProxies: getEnv("TRUSTED_PROXIES", ""),

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
