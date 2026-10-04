package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestConfig_AdminAppSignInPolicy_DefaultOffAndNormalized(t *testing.T) {
	t.Setenv("ADMIN_APP_SIGNIN_POLICY", "")
	if got := Load().AdminAppSignInPolicy; got != "off" {
		t.Errorf("default = %q, want off", got)
	}
	for in, want := range map[string]string{" Enforce ": "enforce", "observe": "observe", "bogus": "off"} {
		t.Setenv("ADMIN_APP_SIGNIN_POLICY", in)
		if got := Load().AdminAppSignInPolicy; got != want {
			t.Errorf("ADMIN_APP_SIGNIN_POLICY=%q -> %q, want %q", in, got, want)
		}
	}
}

func TestConfig_ConsoleClientIDs(t *testing.T) {
	c := &Config{OperatorConsoleClientIDs: " admin-bff, ,monitoring-bff,admin-bff", AdminConsoleClientID: "admin-spa"}
	want := []string{"admin-bff", "monitoring-bff", "admin-spa"}
	if got := c.ConsoleClientIDs(); !reflect.DeepEqual(got, want) {
		t.Errorf("ConsoleClientIDs = %v, want %v", got, want)
	}
	if got := (&Config{}).ConsoleClientIDs(); len(got) != 0 {
		t.Errorf("no console configured: %v", got)
	}
}

// enforce without any console would lock every operator out: refuse to start,
// in every environment.
func TestConfig_Validate_AdminAppSignInEnforceNeedsAConsole(t *testing.T) {
	c := &Config{Environment: "development", AdminAppSignInPolicy: "enforce"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "OPERATOR_CONSOLE_CLIENT_IDS") {
		t.Fatalf("Validate = %v, want an error naming OPERATOR_CONSOLE_CLIENT_IDS", err)
	}
	c.OperatorConsoleClientIDs = "admin-bff"
	if err := c.Validate(); err != nil {
		t.Fatalf("with a console: %v", err)
	}
	c = &Config{Environment: "development", AdminAppSignInPolicy: "enforce", AdminConsoleClientID: "admin-spa"}
	if err := c.Validate(); err != nil {
		t.Fatalf("ADMIN_CONSOLE_CLIENT_ID counts as a console: %v", err)
	}
	if err := (&Config{Environment: "development", AdminAppSignInPolicy: "observe"}).Validate(); err != nil {
		t.Fatalf("observe needs no console: %v", err)
	}
}

func TestConfig_AdminAPIAudienceMode(t *testing.T) {
	t.Setenv("ADMIN_API_AUDIENCE_MODE", "")
	if got := Load().AdminAPIAudienceMode; got != "off" {
		t.Errorf("default = %q, want off", got)
	}
	t.Setenv("ADMIN_API_AUDIENCE_MODE", " ENFORCE ")
	if got := Load().AdminAPIAudienceMode; got != "enforce" {
		t.Errorf("normalised = %q, want enforce", got)
	}
	c := &Config{Environment: "development", AdminAPIAudienceMode: "enforce"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ADMIN_API_AUDIENCE_MODE") {
		t.Fatalf("enforce without a console: %v, want a refusal", err)
	}
	c.OperatorConsoleClientIDs = "admin-bff,monitoring-bff"
	if err := c.Validate(); err != nil {
		t.Fatalf("enforce with consoles: %v", err)
	}
}
