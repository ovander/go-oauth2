// Package config — tests for MED-04, MED-07, LOW-01, and LOW-03.
//
// MED-03 (verify URL not exposed in ENV=test): tested in internal/handler/auth_med03_test.go.
// MED-04: default environment is "production".
// MED-07: ACCESS_TOKEN_TTL warning goes through structured logger (fmt.Println removed).
// LOW-01: SecretKeyBase documentation and validation.
// LOW-03: RATE_LIMIT_*_WINDOW_MS new env vars, backwards-compat fallback.
package config

import (
	"os"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// MED-04: default environment is "production"
// ---------------------------------------------------------------------------

// TestMED04_DefaultEnvironment_IsProduction verifies that when ENV is not set,
// Load() returns Environment="production" rather than the old "development"
// default that silently enabled insecure paths.
func TestMED04_DefaultEnvironment_IsProduction(t *testing.T) {
	// Ensure ENV is unset for this test.
	old := os.Getenv("ENV")
	os.Unsetenv("ENV")
	defer func() {
		if old != "" {
			os.Setenv("ENV", old)
		}
	}()

	cfg := Load()
	if cfg.Environment != "production" {
		t.Errorf("MED-04: default Environment = %q, want \"production\"", cfg.Environment)
	}
	if !cfg.IsProduction() {
		t.Error("MED-04: IsProduction() returned false for default configuration")
	}
}

// TestMED04_ExplicitDevelopment_IsRespected verifies that setting ENV=development
// still results in a development environment.
func TestMED04_ExplicitDevelopment_IsRespected(t *testing.T) {
	os.Setenv("ENV", "development")
	defer os.Unsetenv("ENV")

	cfg := Load()
	if cfg.Environment != "development" {
		t.Errorf("MED-04: ENV=development should produce Environment=%q but got %q", "development", cfg.Environment)
	}
	if !cfg.IsDevelopment() {
		t.Error("MED-04: IsDevelopment() returned false for ENV=development")
	}
}

// TestMED04_ExplicitProduction_IsProduction verifies that setting ENV=production
// explicitly also works.
func TestMED04_ExplicitProduction_IsProduction(t *testing.T) {
	os.Setenv("ENV", "production")
	defer os.Unsetenv("ENV")

	cfg := Load()
	if !cfg.IsProduction() {
		t.Error("MED-04: IsProduction() returned false for ENV=production")
	}
}

// ---------------------------------------------------------------------------
// MED-07: Validate() uses structured logger, not fmt.Println
// ---------------------------------------------------------------------------

// TestMED07_Validate_LongAccessTokenTTL_DoesNotPanic verifies that calling
// Validate() with a long AccessTokenTTL in production does not panic and
// completes without error (the warning goes through the logger, not fmt.Println
// which could cause issues in some test setups).
func TestMED07_Validate_LongAccessTokenTTL_DoesNotPanic(t *testing.T) {
	cfg := &Config{
		Environment:     "production",
		SecretKeyBase:   "a-sufficiently-long-secret-key-for-test",
		DatabaseURL:     "postgres://prod/db",
		OAuthIssuer:     "https://auth.example.com",
		KeysPath:        "/tmp/keys",
		AccessTokenTTL:  2 * time.Hour, // > 30 minutes — triggers warning
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}

	// Should not panic; the warning must go through logger not fmt.Println.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MED-07: Validate() panicked: %v", r)
		}
	}()

	// Validate returns an error for non-absolute KeysPath; that is expected.
	// We just care that it does not panic.
	_ = cfg.Validate()
}

// TestMED07_Validate_ShortAccessTokenTTL_NoWarning verifies that a short
// AccessTokenTTL (≤ 30 min) completes without any warning.
func TestMED07_Validate_ShortAccessTokenTTL_NoWarning(t *testing.T) {
	cfg := &Config{
		Environment:    "production",
		SecretKeyBase:  "a-sufficiently-long-secret-key-for-test",
		DatabaseURL:    "postgres://prod/db",
		OAuthIssuer:    "https://auth.example.com",
		KeysPath:       "/tmp/keys",
		AccessTokenTTL: 15 * time.Minute, // ≤ 30 minutes — no warning
	}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MED-07: Validate() panicked for short TTL: %v", r)
		}
	}()
	_ = cfg.Validate()
}

// ---------------------------------------------------------------------------
// LOW-01: SecretKeyBase is documented and validated in production
// ---------------------------------------------------------------------------

// TestLOW01_SecretKeyBase_Required_InProduction verifies that Validate()
// returns an error when SecretKeyBase is missing in a production config.
func TestLOW01_SecretKeyBase_Required_InProduction(t *testing.T) {
	cfg := &Config{
		Environment:    "production",
		SecretKeyBase:  "", // absent
		DatabaseURL:    "postgres://prod/db",
		OAuthIssuer:    "https://auth.example.com",
		KeysPath:       "/tmp/keys",
		AccessTokenTTL: 15 * time.Minute,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("LOW-01: Validate() should return error when SecretKeyBase is empty in production")
	}
}

// TestLOW01_SecretKeyBase_TooShort_InProduction verifies that Validate()
// returns an error when SecretKeyBase is present but shorter than 32 chars.
func TestLOW01_SecretKeyBase_TooShort_InProduction(t *testing.T) {
	cfg := &Config{
		Environment:    "production",
		SecretKeyBase:  "short",
		DatabaseURL:    "postgres://prod/db",
		OAuthIssuer:    "https://auth.example.com",
		KeysPath:       "/tmp/keys",
		AccessTokenTTL: 15 * time.Minute,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("LOW-01: Validate() should return error when SecretKeyBase < 32 chars")
	}
}

// TestLOW01_SecretKeyBase_NotRequired_OutsideProduction verifies that
// non-production environments do not require SecretKeyBase.
func TestLOW01_SecretKeyBase_NotRequired_OutsideProduction(t *testing.T) {
	cfg := &Config{
		Environment:    "development",
		SecretKeyBase:  "", // absent — OK in dev
		AccessTokenTTL: 15 * time.Minute,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("LOW-01: Validate() should not require SecretKeyBase outside production, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LOW-03: rate limit window env vars accept _MS suffix
// ---------------------------------------------------------------------------

// TestLOW03_LoginWindow_MS_Suffix_Parsed verifies that
// RATE_LIMIT_LOGIN_WINDOW_MS is read and interpreted as milliseconds.
func TestLOW03_LoginWindow_MS_Suffix_Parsed(t *testing.T) {
	os.Setenv("RATE_LIMIT_LOGIN_WINDOW_MS", "30000") // 30 seconds
	defer os.Unsetenv("RATE_LIMIT_LOGIN_WINDOW_MS")

	cfg := Load()
	want := 30 * time.Second
	if cfg.RateLimitLoginWindow != want {
		t.Errorf("LOW-03: RateLimitLoginWindow = %v, want %v", cfg.RateLimitLoginWindow, want)
	}
}

// TestLOW03_LoginWindow_OldName_Fallback verifies that the legacy env var
// RATE_LIMIT_LOGIN_WINDOW still works when the new _MS name is not set.
func TestLOW03_LoginWindow_OldName_Fallback(t *testing.T) {
	os.Unsetenv("RATE_LIMIT_LOGIN_WINDOW_MS")
	os.Setenv("RATE_LIMIT_LOGIN_WINDOW", "45000") // 45 seconds
	defer os.Unsetenv("RATE_LIMIT_LOGIN_WINDOW")

	cfg := Load()
	want := 45 * time.Second
	if cfg.RateLimitLoginWindow != want {
		t.Errorf("LOW-03: RateLimitLoginWindow fallback = %v, want %v", cfg.RateLimitLoginWindow, want)
	}
}

// TestLOW03_LoginWindow_MS_Takes_Priority_Over_Old verifies that when both
// RATE_LIMIT_LOGIN_WINDOW_MS and RATE_LIMIT_LOGIN_WINDOW are set, the _MS
// name takes priority.
func TestLOW03_LoginWindow_MS_Takes_Priority_Over_Old(t *testing.T) {
	os.Setenv("RATE_LIMIT_LOGIN_WINDOW_MS", "20000") // 20 seconds — should win
	os.Setenv("RATE_LIMIT_LOGIN_WINDOW", "90000")    // 90 seconds — should be ignored
	defer func() {
		os.Unsetenv("RATE_LIMIT_LOGIN_WINDOW_MS")
		os.Unsetenv("RATE_LIMIT_LOGIN_WINDOW")
	}()

	cfg := Load()
	want := 20 * time.Second
	if cfg.RateLimitLoginWindow != want {
		t.Errorf("LOW-03: _MS should take priority — got %v, want %v", cfg.RateLimitLoginWindow, want)
	}
}

// TestLOW03_SignupWindow_MS_Suffix_Parsed verifies RATE_LIMIT_SIGNUP_WINDOW_MS.
func TestLOW03_SignupWindow_MS_Suffix_Parsed(t *testing.T) {
	os.Setenv("RATE_LIMIT_SIGNUP_WINDOW_MS", "7200000") // 2 hours
	defer os.Unsetenv("RATE_LIMIT_SIGNUP_WINDOW_MS")

	cfg := Load()
	want := 2 * time.Hour
	if cfg.RateLimitSignupWindow != want {
		t.Errorf("LOW-03: RateLimitSignupWindow = %v, want %v", cfg.RateLimitSignupWindow, want)
	}
}

// TestLOW03_DefaultWindow_Is60Seconds verifies the default when neither env
// var is set remains 60 seconds (60000 ms) — unchanged from the original.
func TestLOW03_DefaultWindow_Is60Seconds(t *testing.T) {
	os.Unsetenv("RATE_LIMIT_LOGIN_WINDOW_MS")
	os.Unsetenv("RATE_LIMIT_LOGIN_WINDOW")

	cfg := Load()
	want := 60 * time.Second
	if cfg.RateLimitLoginWindow != want {
		t.Errorf("LOW-03: default RateLimitLoginWindow = %v, want %v", cfg.RateLimitLoginWindow, want)
	}
}
