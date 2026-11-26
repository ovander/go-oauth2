package config

import "testing"

func TestConfig_RecoveryCodesReverifyMode_Normalised(t *testing.T) {
	t.Setenv("MFA_RECOVERY_CODES_REVERIFY_MODE", "")
	if got := Load().RecoveryCodesReverifyMode; got != "off" {
		t.Errorf("default = %q, want off", got)
	}
	for in, want := range map[string]string{
		"observe":   "observe",
		" Enforce ": "enforce",
		"ENFORCE":   "enforce",
		"off":       "off",
		"bogus":     "off",
	} {
		t.Setenv("MFA_RECOVERY_CODES_REVERIFY_MODE", in)
		if got := Load().RecoveryCodesReverifyMode; got != want {
			t.Errorf("MFA_RECOVERY_CODES_REVERIFY_MODE=%q -> %q, want %q", in, got, want)
		}
	}
}
