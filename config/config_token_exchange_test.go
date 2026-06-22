package config

import (
	"os"
	"testing"
)

func TestConfig_TokenExchangeMode_DefaultOff(t *testing.T) {
	if err := os.Unsetenv("TOKEN_EXCHANGE_MODE"); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if got := Load().TokenExchangeMode; got != "off" {
		t.Errorf("TokenExchangeMode default = %q, want \"off\"", got)
	}
}

func TestConfig_TokenExchangeMode_Normalizes(t *testing.T) {
	cases := map[string]string{
		"shadow":   "shadow",
		"SHADOW":   "shadow",
		" enforce": "enforce",
		"off":      "off",
		"bogus":    "off", // fail safe
	}
	for in, want := range cases {
		t.Setenv("TOKEN_EXCHANGE_MODE", in)
		if got := Load().TokenExchangeMode; got != want {
			t.Errorf("TOKEN_EXCHANGE_MODE=%q -> %q, want %q", in, got, want)
		}
	}
}
