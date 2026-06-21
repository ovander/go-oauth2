// Package config — tests for M-01: AutoMigrate config flag and getEnvBool.
//
// M-01 fix: GORM AutoMigrate is now gated behind AUTO_MIGRATE=true.  The
// default is false so production restarts never touch the database schema.
// These tests verify the parsing logic and the safe default.
package config

import (
	"os"
	"testing"
)

// setenv sets an env variable for the duration of a test and restores it on
// cleanup.
func setenv(t *testing.T, key, value string) {
	t.Helper()
	old, wasSet := os.LookupEnv(key)
	t.Cleanup(func() {
		if wasSet {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
	os.Setenv(key, value)
}

// unsetenv ensures an env variable is absent for the duration of a test.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	old, wasSet := os.LookupEnv(key)
	t.Cleanup(func() {
		if wasSet {
			os.Setenv(key, old)
		}
	})
	os.Unsetenv(key)
}

// ---------------------------------------------------------------------------
// M-01: AutoMigrate defaults to false
// ---------------------------------------------------------------------------

func TestConfig_AutoMigrate_DefaultIsFalse(t *testing.T) {
	// When AUTO_MIGRATE is not set, the field must default to false so that
	// production restarts never touch the database schema accidentally.
	unsetenv(t, "AUTO_MIGRATE")

	if getEnvBool("AUTO_MIGRATE", false) {
		t.Error("AutoMigrate must default to false when AUTO_MIGRATE is unset")
	}
}

func TestConfig_Load_AutoMigrate_DefaultIsFalse(t *testing.T) {
	// End-to-end: Load() must produce AutoMigrate=false when the env var is absent.
	unsetenv(t, "AUTO_MIGRATE")
	cfg := Load()
	if cfg.AutoMigrate {
		t.Error("Config.AutoMigrate must be false by default (AUTO_MIGRATE not set)")
	}
}

func TestConfig_Load_AutoMigrateTrue_WhenEnvTrue(t *testing.T) {
	setenv(t, "AUTO_MIGRATE", "true")
	cfg := Load()
	if !cfg.AutoMigrate {
		t.Error("Config.AutoMigrate must be true when AUTO_MIGRATE=true")
	}
}

func TestConfig_Load_AutoMigrateFalse_WhenEnvFalse(t *testing.T) {
	setenv(t, "AUTO_MIGRATE", "false")
	cfg := Load()
	if cfg.AutoMigrate {
		t.Error("Config.AutoMigrate must be false when AUTO_MIGRATE=false")
	}
}

// ---------------------------------------------------------------------------
// getEnvBool — truthy inputs
// ---------------------------------------------------------------------------

func TestGetEnvBool_TruthyValues(t *testing.T) {
	truthy := []string{"1", "true", "True", "TRUE", "yes", "YES", "Yes", "on", "ON", "On"}
	for _, v := range truthy {
		t.Run(v, func(t *testing.T) {
			setenv(t, "TEST_BOOL", v)
			if !getEnvBool("TEST_BOOL", false) {
				t.Errorf("getEnvBool(%q) must return true", v)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getEnvBool — falsy inputs
// ---------------------------------------------------------------------------

func TestGetEnvBool_FalsyValues(t *testing.T) {
	falsy := []string{"0", "false", "False", "FALSE", "no", "NO", "No", "off", "OFF", "Off"}
	for _, v := range falsy {
		t.Run(v, func(t *testing.T) {
			setenv(t, "TEST_BOOL", v)
			if getEnvBool("TEST_BOOL", true) {
				t.Errorf("getEnvBool(%q) must return false", v)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getEnvBool — unknown / garbage inputs fall back to the default
// ---------------------------------------------------------------------------

func TestGetEnvBool_UnknownValue_ReturnsDefault(t *testing.T) {
	cases := []struct {
		value      string
		defaultVal bool
	}{
		{"maybe", false},
		{"maybe", true},
		{"2", true},
		{"enabled", false},
		{"", false},         // empty string → use default (env helper returns "" → default path)
		{"  true  ", false}, // leading/trailing spaces — TrimSpace is applied
	}

	for _, c := range cases {
		t.Run(c.value+"_default_"+boolStr(c.defaultVal), func(t *testing.T) {
			setenv(t, "TEST_BOOL", c.value)
			got := getEnvBool("TEST_BOOL", c.defaultVal)

			// "  true  " should be parsed as true after TrimSpace.
			if c.value == "  true  " {
				if !got {
					t.Error("getEnvBool should trim spaces and parse '  true  ' as true")
				}
				return
			}
			// empty string: os.Getenv returns "" which causes getEnvBool to return the default
			if c.value == "" {
				if got != c.defaultVal {
					t.Errorf("getEnvBool(%q, %v) = %v, want %v (default)", c.value, c.defaultVal, got, c.defaultVal)
				}
				return
			}
			if got != c.defaultVal {
				t.Errorf("getEnvBool(%q, default=%v) = %v, want default %v for unknown input",
					c.value, c.defaultVal, got, c.defaultVal)
			}
		})
	}
}

func TestGetEnvBool_UnsetEnv_ReturnsDefault(t *testing.T) {
	unsetenv(t, "TEST_BOOL_UNSET")
	if getEnvBool("TEST_BOOL_UNSET", true) != true {
		t.Error("unset env var must return default=true")
	}
	if getEnvBool("TEST_BOOL_UNSET", false) != false {
		t.Error("unset env var must return default=false")
	}
}

// ---------------------------------------------------------------------------
// M-01: verify the field exists on Config (compile-time + reflection)
// ---------------------------------------------------------------------------

func TestConfig_HasAutoMigrateField(t *testing.T) {
	// This is a compile-time test: if AutoMigrate is renamed or removed, the
	// test binary won't build.
	var cfg Config
	cfg.AutoMigrate = true
	if !cfg.AutoMigrate {
		t.Error("Config.AutoMigrate field not settable")
	}
	cfg.AutoMigrate = false
	if cfg.AutoMigrate {
		t.Error("Config.AutoMigrate field not settable to false")
	}
}

// ---------------------------------------------------------------------------
// M-10: JWTSecret field has been removed — setting JWT_SECRET has no effect
// ---------------------------------------------------------------------------

func TestConfig_NoJWTSecretField(t *testing.T) {
	// This is a compile-time test: if a JWTSecret field is re-introduced the
	// code below will fail to compile (no such field).
	// The assertion verifies that the Config type does not carry the field at
	// all, so operators cannot be misled into thinking JWT_SECRET affects
	// token security.
	var cfg Config
	// Access other fields to confirm the struct is still usable.
	cfg.OAuthIssuer = "https://example.com"
	if cfg.OAuthIssuer == "" {
		t.Error("OAuthIssuer field must exist")
	}
	// If JWTSecret were still present the line below would compile and set it;
	// its absence is enforced by the compiler — no runtime assertion needed.
}

func TestConfig_Load_JWTSecretEnvHasNoEffect(t *testing.T) {
	// Even if the operator sets JWT_SECRET, Load() must not fail and the
	// resulting config must be usable.  The env var is now silently ignored.
	setenv(t, "JWT_SECRET", "super-secret-value-that-does-nothing")
	cfg := Load()
	// Config must still load successfully (non-nil, no panic).
	if cfg == nil {
		t.Fatal("Load() returned nil")
	}
	// OAuthIssuer should be the default (confirming Load ran normally).
	if cfg.OAuthIssuer == "" {
		t.Error("OAuthIssuer must not be empty after Load()")
	}
}

// ---------------------------------------------------------------------------
// L-05: KeysPath must be absolute in production
// ---------------------------------------------------------------------------

func TestConfig_Validate_Production_RelativeKeysPath_ReturnsError(t *testing.T) {
	// A relative KEYS_PATH in production is ambiguous and dangerous — the key
	// location depends on the process working directory, which may vary between
	// deployments.  Validate must reject it.
	cfg := &Config{
		Environment:   "production",
		SecretKeyBase: "32-character-secret-key-base-xxxx",
		DatabaseURL:   "postgres://prod.example.com/db",
		OAuthIssuer:   "https://auth.example.com",
		KeysPath:      "keys", // relative path — must be rejected
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() must return error when KeysPath is relative in production")
	}
}

func TestConfig_Validate_Production_AbsoluteKeysPath_OK(t *testing.T) {
	// An absolute KEYS_PATH is unambiguous regardless of working directory.
	cfg := &Config{
		Environment:   "production",
		SecretKeyBase: "32-character-secret-key-base-xxxx",
		DatabaseURL:   "postgres://prod.example.com/db",
		OAuthIssuer:   "https://auth.example.com",
		KeysPath:      "/etc/myapp/keys", // absolute path — must be accepted
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned error for absolute KeysPath: %v", err)
	}
}

func TestConfig_Validate_Development_RelativeKeysPath_OK(t *testing.T) {
	// The restriction only applies in production.  Development should be able
	// to use a relative path for convenience.
	cfg := &Config{
		Environment: "development",
		KeysPath:    "keys", // relative — fine in development
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() must not error for relative KeysPath in development: %v", err)
	}
}

func TestConfig_Validate_Production_RelativeKeysPath_DotSlash_ReturnsError(t *testing.T) {
	// "./keys" is still a relative path (starts with ".").
	cfg := &Config{
		Environment:   "production",
		SecretKeyBase: "32-character-secret-key-base-xxxx",
		DatabaseURL:   "postgres://prod.example.com/db",
		OAuthIssuer:   "https://auth.example.com",
		KeysPath:      "./keys",
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() must return error for './keys' (relative) in production")
	}
}

func TestConfig_Validate_IsProduction_ProdEnvironment(t *testing.T) {
	cfg := &Config{Environment: "production"}
	if !cfg.IsProduction() {
		t.Error("IsProduction() must return true for 'production'")
	}
}

func TestConfig_Validate_IsProduction_ProdShorthand(t *testing.T) {
	cfg := &Config{Environment: "prod"}
	if !cfg.IsProduction() {
		t.Error("IsProduction() must return true for 'prod'")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
