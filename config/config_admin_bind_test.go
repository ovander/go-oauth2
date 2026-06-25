package config

import "testing"

// The admin API must bind loopback by default so the Tier-0 control plane is not
// publicly reachable without an external firewall.
func TestConfig_AdminBindHost_DefaultsToLoopback(t *testing.T) {
	setenv(t, "ADMIN_BIND_HOST", "")
	cfg := Load()
	if cfg.AdminBindHost != "127.0.0.1" {
		t.Fatalf("AdminBindHost default: got %q, want 127.0.0.1", cfg.AdminBindHost)
	}
}

func TestConfig_AdminBindHost_OverrideForMultiHost(t *testing.T) {
	setenv(t, "ADMIN_BIND_HOST", "0.0.0.0")
	cfg := Load()
	if cfg.AdminBindHost != "0.0.0.0" {
		t.Fatalf("AdminBindHost override: got %q, want 0.0.0.0", cfg.AdminBindHost)
	}
}
