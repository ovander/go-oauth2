package config

import (
	"os"
	"testing"
)

func TestConfig_DPoPMode_DefaultOff(t *testing.T) {
	if err := os.Unsetenv("DPOP_MODE"); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if got := Load().DPoPMode; got != "off" {
		t.Errorf("DPoPMode default = %q, want \"off\"", got)
	}
}

func TestConfig_DPoPMode_Normalizes(t *testing.T) {
	cases := map[string]string{
		"observe":   "observe",
		"OBSERVE":   "observe",
		" enforce ": "enforce",
		"off":       "off",
		"nonsense":  "off", // unrecognized fails safe to off
	}
	for in, want := range cases {
		t.Setenv("DPOP_MODE", in)
		if got := Load().DPoPMode; got != want {
			t.Errorf("DPOP_MODE=%q -> %q, want %q", in, got, want)
		}
	}
}
