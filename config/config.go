package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
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
	JWTSecret   string
	OAuthIssuer string

	// Token TTLs
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	EmailTokenTTL   time.Duration
	ResetTokenTTL   time.Duration
	InviteTokenTTL  time.Duration

	// Security
	MaxFailedAttempts   int
	LockoutDurationSecs int
	SecretKeyBase       string

	// Rate Limiting
	RateLimitLogin        int
	RateLimitLoginWindow  time.Duration
	RateLimitSignup       int
	RateLimitSignupWindow time.Duration
	RateLimitMaxEntries   int

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

	// GeoIP
	GeoIPCityDBPath string // Path to GeoLite2-City.mmdb
	GeoIPASNDBPath  string // Path to GeoLite2-ASN.mmdb (optional)
}

// Load loads configuration from environment variables
func Load() *Config {
	// Load .env file (ignore error in production)
	_ = godotenv.Load()

	cfg := &Config{
		// Server
		Port:        getEnv("PORT", "8080"),
		AdminPort:   getEnv("ADMIN_PORT", ""), // Empty = disabled (use single port mode)
		Host:        getEnv("PHX_HOST", "localhost"),
		Environment: getEnv("ENV", "development"),

		// Database
		DatabaseURL: getEnv("DATABASE_URL", "postgres://localhost/socrate_auth_dev"),
		DBPoolSize:  getEnvInt("DB_POOL_SIZE", 10),
		DBTimeout:   time.Duration(getEnvInt("DB_TIMEOUT_SECONDS", 30)) * time.Second,

		// JWT
		JWTSecret:   getEnv("JWT_SECRET", ""),
		OAuthIssuer: getEnv("OAUTH_ISSUER", "http://localhost:8080"),

		// Token TTLs
		AccessTokenTTL:  time.Duration(getEnvInt("ACCESS_TOKEN_TTL", 900)) * time.Second,
		RefreshTokenTTL: time.Duration(getEnvInt("REFRESH_TOKEN_TTL", 604800)) * time.Second,
		EmailTokenTTL:   time.Duration(getEnvInt("EMAIL_TOKEN_TTL", 86400)) * time.Second,
		ResetTokenTTL:   time.Duration(getEnvInt("RESET_TOKEN_TTL", 3600)) * time.Second,
		InviteTokenTTL:  time.Duration(getEnvInt("INVITE_TOKEN_TTL", 86400)) * time.Second,

		// Security
		MaxFailedAttempts:   getEnvInt("MAX_FAILED_ATTEMPTS", 5),
		LockoutDurationSecs: getEnvInt("LOCKOUT_DURATION_SECONDS", 900),
		SecretKeyBase:       getEnv("SECRET_KEY_BASE", ""),

		// Rate Limiting
		RateLimitLogin:        getEnvInt("RATE_LIMIT_LOGIN", 5),
		RateLimitLoginWindow:  time.Duration(getEnvInt("RATE_LIMIT_LOGIN_WINDOW", 60000)) * time.Millisecond,
		RateLimitSignup:       getEnvInt("RATE_LIMIT_SIGNUP", 3),
		RateLimitSignupWindow: time.Duration(getEnvInt("RATE_LIMIT_SIGNUP_WINDOW", 3600000)) * time.Millisecond,
		RateLimitMaxEntries:   getEnvInt("RATE_LIMIT_MAX_ENTRIES", 10000),

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

		// GeoIP
		GeoIPCityDBPath: getEnv("GEOIP_CITY_DB", ""),
		GeoIPASNDBPath:  getEnv("GEOIP_ASN_DB", ""),
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
		// Warn about insecure defaults
		if c.AccessTokenTTL > 30*time.Minute {
			fmt.Println("WARNING: ACCESS_TOKEN_TTL is set to more than 30 minutes, consider reducing for better security")
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

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}
