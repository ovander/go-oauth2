package config

import (
	"testing"
	"time"
)

// ALERT_RULES_MODE (#258): off by default; observe and enforce; anything else
// is off. The interval is at least 10 seconds.
func TestConfig_AlertRules(t *testing.T) {
	t.Setenv("ALERT_RULES_MODE", "")
	t.Setenv("ALERT_RULES_INTERVAL_SECONDS", "")
	cfg := Load()
	if cfg.AlertRulesMode != "off" || cfg.AlertRulesInterval != time.Minute {
		t.Errorf("defaults = %q, %v; want off, 1m", cfg.AlertRulesMode, cfg.AlertRulesInterval)
	}
	for in, want := range map[string]string{"observe": "observe", " Enforce ": "enforce", "on": "off", "bogus": "off"} {
		t.Setenv("ALERT_RULES_MODE", in)
		if got := Load().AlertRulesMode; got != want {
			t.Errorf("ALERT_RULES_MODE=%q -> %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]time.Duration{"300": 5 * time.Minute, "10": 10 * time.Second, "1": 10 * time.Second, "0": 10 * time.Second} {
		t.Setenv("ALERT_RULES_INTERVAL_SECONDS", in)
		if got := Load().AlertRulesInterval; got != want {
			t.Errorf("ALERT_RULES_INTERVAL_SECONDS=%q -> %v, want %v", in, got, want)
		}
	}
}
