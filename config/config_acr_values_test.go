package config

import "testing"

func TestConfig_ACRValuesMode_Normalised(t *testing.T) {
	t.Setenv("ACR_VALUES_MODE", "")
	if got := Load().ACRValuesMode; got != "off" {
		t.Errorf("default = %q, want off", got)
	}
	for in, want := range map[string]string{
		"observe": "observe", " Enforce ": "enforce", "off": "off", "bogus": "off",
	} {
		t.Setenv("ACR_VALUES_MODE", in)
		if got := Load().ACRValuesMode; got != want {
			t.Errorf("ACR_VALUES_MODE=%q -> %q, want %q", in, got, want)
		}
	}
}
