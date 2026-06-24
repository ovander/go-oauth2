package main

import (
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/config"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

func findEntry(entries []*logrus.Entry, msg string) *logrus.Entry {
	for _, e := range entries {
		if e.Message == msg {
			return e
		}
	}
	return nil
}

func TestLogStartupSummary_SurfacesConfig(t *testing.T) {
	hook := logrustest.NewLocal(logger.Logger)
	t.Cleanup(hook.Reset)

	LogStartupSummary(&config.Config{
		Environment:          "development",
		OAuthIssuer:          "http://localhost:8080",
		Port:                 "8080",
		AdminPort:            "8081",
		DPoPMode:             "observe",
		TokenExchangeMode:    "off",
		AdminConsoleClientID: "admin-console",
		AdminElevationMaxAge: 5 * time.Minute,
		KeyRotationInterval:  0,
	})

	e := findEntry(hook.AllEntries(), "✅ Socrate initialized — effective configuration")
	if e == nil {
		t.Fatal("no startup summary line emitted")
	}
	if e.Data["mode"] != "dual-port" {
		t.Errorf("mode = %v, want dual-port", e.Data["mode"])
	}
	if e.Data["dpop_mode"] != "observe" {
		t.Errorf("dpop_mode = %v, want observe", e.Data["dpop_mode"])
	}
	if e.Data["admin_console_pkce"] != true {
		t.Errorf("admin_console_pkce should be true when a client id is set")
	}
	if e.Data["admin_elevation"] != "5m0s" {
		t.Errorf("admin_elevation = %v, want 5m0s", e.Data["admin_elevation"])
	}
	if e.Data["key_rotation"] != "disabled" {
		t.Errorf("key_rotation = %v, want disabled (0)", e.Data["key_rotation"])
	}
}

func TestLogStartupSummary_ProductionWarnings(t *testing.T) {
	hook := logrustest.NewLocal(logger.Logger)
	t.Cleanup(hook.Reset)

	LogStartupSummary(&config.Config{
		Environment:               "production",
		OAuthIssuer:               "http://insecure.example.com", // not https
		AdminPasswordLoginEnabled: true,                          // deprecated flow on
	})

	var warnings int
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			warnings++
		}
	}
	if warnings < 2 {
		t.Errorf("expected production warnings for non-https issuer and enabled password login, got %d", warnings)
	}
}

func TestLogStartupSummary_NoProductionWarningsInDev(t *testing.T) {
	hook := logrustest.NewLocal(logger.Logger)
	t.Cleanup(hook.Reset)

	LogStartupSummary(&config.Config{
		Environment:               "development",
		OAuthIssuer:               "http://localhost:8080",
		AdminPasswordLoginEnabled: true,
	})

	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			t.Errorf("no production warnings expected in development, got: %q", e.Message)
		}
	}
}
