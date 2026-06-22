package service

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

// At DEBUG level, the OAuth flows emit structured trace points that carry the
// request's correlation_id (RFC-008) — verified here via the introspect path.
func TestDebugTrace_Introspect_CarriesCorrelationID(t *testing.T) {
	hook := logrustest.NewLocal(logger.Logger)
	t.Cleanup(hook.Reset)
	prev := logger.Logger.GetLevel()
	logger.Logger.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() { logger.Logger.SetLevel(prev) })

	svc := newNew03Svc(t, &model.User{ID: 100, Email: "a@example.com", TokenVersion: 1})
	ctx := context.WithValue(context.Background(), contextkeys.RequestIDKey, "corr-debug-1")

	if _, err := svc.Introspect(ctx, "not-a-valid-token"); err != nil {
		t.Fatalf("Introspect: %v", err)
	}

	found := false
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.DebugLevel && e.Message == "introspect: inactive" && e.Data["correlation_id"] == "corr-debug-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a DEBUG 'introspect: inactive' trace carrying the correlation_id")
	}
}

// At the default INFO level, the DEBUG traces are suppressed (no noise in prod).
func TestDebugTrace_SuppressedAtInfoLevel(t *testing.T) {
	hook := logrustest.NewLocal(logger.Logger)
	t.Cleanup(hook.Reset)
	prev := logger.Logger.GetLevel()
	logger.Logger.SetLevel(logrus.InfoLevel)
	t.Cleanup(func() { logger.Logger.SetLevel(prev) })

	svc := newNew03Svc(t, &model.User{ID: 100, Email: "a@example.com", TokenVersion: 1})
	_, _ = svc.Introspect(context.Background(), "not-a-valid-token")

	for _, e := range hook.AllEntries() {
		if e.Level == logrus.DebugLevel {
			t.Fatalf("DEBUG trace leaked at INFO level: %q", e.Message)
		}
	}
}
