package config

import (
	"os"
	"testing"
)

func TestConfig_AdminMFAPolicy_DefaultOff(t *testing.T) {
	if err := os.Unsetenv("ADMIN_MFA_POLICY"); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if got := Load().AdminMFAPolicy; got != "off" {
		t.Errorf("AdminMFAPolicy default = %q, want \"off\"", got)
	}
}

func TestConfig_AdminMFAPolicy_NormalizesValues(t *testing.T) {
	cases := map[string]string{
		"observe":   "observe",
		"OBSERVE":   "observe",
		" enforce ": "enforce",
		"Enforce":   "enforce",
		"off":       "off",
		"bogus":     "off", // unrecognized fails safe to off
	}
	for in, want := range cases {
		t.Setenv("ADMIN_MFA_POLICY", in)
		if got := Load().AdminMFAPolicy; got != want {
			t.Errorf("ADMIN_MFA_POLICY=%q -> %q, want %q", in, got, want)
		}
	}
}
