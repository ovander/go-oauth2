package config

import "testing"

func TestConfig_AdminScopeMode_Normalised(t *testing.T) {
	t.Setenv("ADMIN_SCOPE_MODE", "")
	if got := Load().AdminScopeMode; got != "off" {
		t.Errorf("default = %q, want off", got)
	}
	for in, want := range map[string]string{
		"enforce":   "enforce",
		" Enforce ": "enforce",
		"ENFORCE":   "enforce",
		"off":       "off",
		"observe":   "off", // not a mode of this gate
		"bogus":     "off",
	} {
		t.Setenv("ADMIN_SCOPE_MODE", in)
		if got := Load().AdminScopeMode; got != want {
			t.Errorf("ADMIN_SCOPE_MODE=%q -> %q, want %q", in, got, want)
		}
	}
}
