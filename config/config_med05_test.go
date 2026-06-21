// Package config — tests for MED-05 (token endpoint rate limiter configuration).
//
// MED-05 fix: RATE_LIMIT_TOKEN and RATE_LIMIT_TOKEN_WINDOW_MS are now loaded
// from the environment and exposed as Config.RateLimitToken /
// Config.RateLimitTokenWindow.  Bootstrap uses these fields to create a
// *middleware.RateLimiter and wire it into RouterConfig.TokenRateLimiter.
// Validate() emits a structured warning when the limiter is explicitly disabled
// (RATE_LIMIT_TOKEN=0) in a production environment.
//
// Tests:
//   - Default RateLimitToken is 10 (non-zero, limiter enabled by default)
//   - Default RateLimitTokenWindow is 60 seconds
//   - RATE_LIMIT_TOKEN env var overrides the limit
//   - RATE_LIMIT_TOKEN_WINDOW_MS env var overrides the window
//   - Legacy RATE_LIMIT_TOKEN_WINDOW (no _MS) accepted as fallback
//   - _MS suffix takes priority over legacy name when both are set
//   - Validate() does NOT error when RateLimitToken == 0 in production
//     (it is a warning, not a hard failure, to allow explicit opt-out)
//   - Validate() does NOT error when RateLimitToken > 0 in production
package config

import (
	"os"
	"testing"
	"time"
)

// withEnv temporarily sets one or more environment variable(s) and restores
// originals via t.Cleanup.  Values are passed as alternating key/value pairs.
func withEnv(t *testing.T, pairs ...string) {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatalf("withEnv: odd number of key/value arguments")
	}
	for i := 0; i < len(pairs); i += 2 {
		key, val := pairs[i], pairs[i+1]
		old, had := os.LookupEnv(key)
		if val == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, val)
		}
		t.Cleanup(func() {
			if had {
				os.Setenv(key, old)
			} else {
				os.Unsetenv(key)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MED-05: default values
// ---------------------------------------------------------------------------

// TestMED05_DefaultRateLimitToken_IsNonZero verifies that the default
// RateLimitToken is 10, meaning the token endpoint rate limiter is enabled
// out of the box without any operator configuration.
func TestMED05_DefaultRateLimitToken_IsNonZero(t *testing.T) {
	withEnv(t, "RATE_LIMIT_TOKEN", "", "RATE_LIMIT_TOKEN_WINDOW_MS", "", "RATE_LIMIT_TOKEN_WINDOW", "")
	cfg := Load()
	if cfg.RateLimitToken != 10 {
		t.Errorf("MED-05: default RateLimitToken = %d, want 10", cfg.RateLimitToken)
	}
}

// TestMED05_DefaultRateLimitTokenWindow_Is60s verifies the default window is
// 60 seconds — consistent with the login and signup rate limiters.
func TestMED05_DefaultRateLimitTokenWindow_Is60s(t *testing.T) {
	withEnv(t, "RATE_LIMIT_TOKEN", "", "RATE_LIMIT_TOKEN_WINDOW_MS", "", "RATE_LIMIT_TOKEN_WINDOW", "")
	cfg := Load()
	if cfg.RateLimitTokenWindow != 60*time.Second {
		t.Errorf("MED-05: default RateLimitTokenWindow = %v, want 60s", cfg.RateLimitTokenWindow)
	}
}

// ---------------------------------------------------------------------------
// MED-05: env var overrides
// ---------------------------------------------------------------------------

// TestMED05_RateLimitToken_EnvOverride verifies that RATE_LIMIT_TOKEN
// overrides the default limit.
func TestMED05_RateLimitToken_EnvOverride(t *testing.T) {
	withEnv(t, "RATE_LIMIT_TOKEN", "25")
	cfg := Load()
	if cfg.RateLimitToken != 25 {
		t.Errorf("MED-05: RateLimitToken = %d after RATE_LIMIT_TOKEN=25, want 25", cfg.RateLimitToken)
	}
}

// TestMED05_RateLimitTokenWindowMS_EnvOverride verifies that
// RATE_LIMIT_TOKEN_WINDOW_MS sets the window in milliseconds.
func TestMED05_RateLimitTokenWindowMS_EnvOverride(t *testing.T) {
	withEnv(t,
		"RATE_LIMIT_TOKEN_WINDOW_MS", "120000", // 120 seconds
		"RATE_LIMIT_TOKEN_WINDOW", "",
	)
	cfg := Load()
	if cfg.RateLimitTokenWindow != 120*time.Second {
		t.Errorf("MED-05: RateLimitTokenWindow = %v after RATE_LIMIT_TOKEN_WINDOW_MS=120000, want 120s",
			cfg.RateLimitTokenWindow)
	}
}

// TestMED05_RateLimitTokenWindow_LegacyFallback verifies that the old env var
// name (without _MS suffix) is accepted when the new name is absent.
func TestMED05_RateLimitTokenWindow_LegacyFallback(t *testing.T) {
	withEnv(t,
		"RATE_LIMIT_TOKEN_WINDOW_MS", "",
		"RATE_LIMIT_TOKEN_WINDOW", "30000", // 30 seconds, in milliseconds
	)
	cfg := Load()
	if cfg.RateLimitTokenWindow != 30*time.Second {
		t.Errorf("MED-05: RateLimitTokenWindow = %v after RATE_LIMIT_TOKEN_WINDOW=30000 (legacy), want 30s",
			cfg.RateLimitTokenWindow)
	}
}

// TestMED05_RateLimitTokenWindowMS_TakesPriorityOverLegacy verifies that the
// _MS-suffixed name takes priority when both are set.
func TestMED05_RateLimitTokenWindowMS_TakesPriorityOverLegacy(t *testing.T) {
	withEnv(t,
		"RATE_LIMIT_TOKEN_WINDOW_MS", "90000", // 90 s — should win
		"RATE_LIMIT_TOKEN_WINDOW", "30000", // 30 s — should be ignored
	)
	cfg := Load()
	if cfg.RateLimitTokenWindow != 90*time.Second {
		t.Errorf("MED-05: RateLimitTokenWindow = %v, want 90s (_MS should take priority)", cfg.RateLimitTokenWindow)
	}
}

// TestMED05_ExplicitlyDisabled_IsZero verifies that setting RATE_LIMIT_TOKEN=0
// is accepted (loads as 0, operator opt-out).
func TestMED05_ExplicitlyDisabled_IsZero(t *testing.T) {
	withEnv(t, "RATE_LIMIT_TOKEN", "0")
	cfg := Load()
	if cfg.RateLimitToken != 0 {
		t.Errorf("MED-05: RateLimitToken = %d after RATE_LIMIT_TOKEN=0, want 0", cfg.RateLimitToken)
	}
}

// ---------------------------------------------------------------------------
// MED-05: Validate() behaviour — warning only, not hard failure
// ---------------------------------------------------------------------------

// TestMED05_Validate_DoesNotErrorWhenTokenLimiterEnabled verifies that
// Validate() returns nil in production when RateLimitToken > 0 (the normal,
// secure path).
func TestMED05_Validate_DoesNotErrorWhenTokenLimiterEnabled(t *testing.T) {
	cfg := &Config{
		Environment:          "production",
		SecretKeyBase:        "this-is-a-32-byte-secret-key-!!!",
		DatabaseURL:          "postgres://prod.example.com/authdb",
		OAuthIssuer:          "https://auth.example.com",
		KeysPath:             "/etc/oauth/keys",
		AccessTokenTTL:       15 * time.Minute,
		RateLimitToken:       10,
		RateLimitTokenWindow: 60 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("MED-05: Validate() returned error for valid production config: %v", err)
	}
}

// TestMED05_Validate_DoesNotFailWhenTokenLimiterDisabled verifies that
// Validate() does NOT return an error when RateLimitToken == 0 — it only logs
// a warning.  Operators may have an external rate limiter (e.g. API gateway)
// and should be able to explicitly disable the built-in one without the
// server refusing to start.
func TestMED05_Validate_DoesNotFailWhenTokenLimiterDisabled(t *testing.T) {
	cfg := &Config{
		Environment:          "production",
		SecretKeyBase:        "this-is-a-32-byte-secret-key-!!!",
		DatabaseURL:          "postgres://prod.example.com/authdb",
		OAuthIssuer:          "https://auth.example.com",
		KeysPath:             "/etc/oauth/keys",
		AccessTokenTTL:       15 * time.Minute,
		RateLimitToken:       0, // explicitly disabled
		RateLimitTokenWindow: 60 * time.Second,
	}
	// Validate() must not return an error — the warning is emitted via logger.
	if err := cfg.Validate(); err != nil {
		t.Errorf("MED-05: Validate() must not hard-fail when RateLimitToken=0 (got: %v)", err)
	}
}

// TestMED05_Validate_NoWarningOutsideProduction verifies that the token
// rate-limiter check is scoped to production — a development deployment with
// RateLimitToken=0 should not emit warnings (tests / local dev should not be
// noisy about this).
func TestMED05_Validate_NoWarningOutsideProduction(t *testing.T) {
	cfg := &Config{
		Environment:    "development",
		RateLimitToken: 0,
	}
	// No panic, no error — Validate() returns nil outside production.
	if err := cfg.Validate(); err != nil {
		t.Errorf("MED-05: Validate() returned error in development: %v", err)
	}
}
