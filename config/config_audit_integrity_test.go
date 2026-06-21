package config

import (
	"os"
	"testing"
	"time"
)

func TestConfig_AuditIntegrityScan_Defaults(t *testing.T) {
	t.Setenv("AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS", "")
	t.Setenv("AUDIT_INTEGRITY_SCAN_LOOKBACK_SECONDS", "")
	if err := os.Unsetenv("AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS"); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if err := os.Unsetenv("AUDIT_INTEGRITY_SCAN_LOOKBACK_SECONDS"); err != nil {
		t.Fatalf("unset: %v", err)
	}

	cfg := Load()

	if cfg.AuditIntegrityScanInterval != 0 {
		t.Errorf("AuditIntegrityScanInterval default = %v, want 0 (disabled)", cfg.AuditIntegrityScanInterval)
	}
	if cfg.AuditIntegrityScanLookback != 24*time.Hour {
		t.Errorf("AuditIntegrityScanLookback default = %v, want 24h", cfg.AuditIntegrityScanLookback)
	}
}

func TestConfig_AuditIntegrityScan_ParsesSeconds(t *testing.T) {
	t.Setenv("AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS", "3600")
	t.Setenv("AUDIT_INTEGRITY_SCAN_LOOKBACK_SECONDS", "7200")

	cfg := Load()

	if cfg.AuditIntegrityScanInterval != time.Hour {
		t.Errorf("AuditIntegrityScanInterval = %v, want 1h", cfg.AuditIntegrityScanInterval)
	}
	if cfg.AuditIntegrityScanLookback != 2*time.Hour {
		t.Errorf("AuditIntegrityScanLookback = %v, want 2h", cfg.AuditIntegrityScanLookback)
	}
}
