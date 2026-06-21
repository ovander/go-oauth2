// Package config — tests for the key-rotation configuration (#12, RFC-002).
package config

import (
	"os"
	"testing"
	"time"
)

func TestConfig_KeyRotation_DefaultsDisabled(t *testing.T) {
	// t.Setenv with empty value, then unset via cleanup-safe helper: setting to
	// "" makes getEnvInt fall back to the default (0). t.Setenv also restores
	// any prior value after the test.
	t.Setenv("KEY_ROTATION_INTERVAL_SECONDS", "")
	t.Setenv("KEY_RETENTION_SECONDS", "")
	if err := os.Unsetenv("KEY_ROTATION_INTERVAL_SECONDS"); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if err := os.Unsetenv("KEY_RETENTION_SECONDS"); err != nil {
		t.Fatalf("unset: %v", err)
	}

	cfg := Load()

	if cfg.KeyRotationInterval != 0 {
		t.Errorf("KeyRotationInterval default = %v, want 0 (disabled)", cfg.KeyRotationInterval)
	}
	if cfg.KeyRetention != 0 {
		t.Errorf("KeyRetention default = %v, want 0 (derive from RefreshTokenTTL)", cfg.KeyRetention)
	}
}

func TestConfig_KeyRotation_ParsesSeconds(t *testing.T) {
	t.Setenv("KEY_ROTATION_INTERVAL_SECONDS", "3600")
	t.Setenv("KEY_RETENTION_SECONDS", "172800")

	cfg := Load()

	if cfg.KeyRotationInterval != time.Hour {
		t.Errorf("KeyRotationInterval = %v, want 1h", cfg.KeyRotationInterval)
	}
	if cfg.KeyRetention != 48*time.Hour {
		t.Errorf("KeyRetention = %v, want 48h", cfg.KeyRetention)
	}
}
