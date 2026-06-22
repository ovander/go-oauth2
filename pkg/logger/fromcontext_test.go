package logger

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/sirupsen/logrus"
)

// FromContext stamps the correlation_id from the context (RFC-008), and is safe
// for a nil/empty context.
func TestFromContext_StampsCorrelationID(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.RequestIDKey, "corr-xyz")
	e := FromContext(ctx)
	if got, ok := e.Data["correlation_id"]; !ok || got != "corr-xyz" {
		t.Fatalf("correlation_id = %v (ok=%v), want corr-xyz", got, ok)
	}
}

func TestFromContext_NilAndEmptySafe(t *testing.T) {
	//nolint:staticcheck // explicitly testing the nil-context path
	if e := FromContext(nil); e == nil {
		t.Fatal("FromContext(nil) must return a usable entry")
	} else if _, ok := e.Data["correlation_id"]; ok {
		t.Error("nil context must not carry a correlation_id")
	}
	if e := FromContext(context.Background()); e == nil {
		t.Fatal("FromContext(bg) must return a usable entry")
	} else if _, ok := e.Data["correlation_id"]; ok {
		t.Error("context without a correlation id must not carry one")
	}
}

// The entry is usable for leveled logging without panicking.
func TestFromContext_Loggable(t *testing.T) {
	old := Logger.Out
	Logger.SetLevel(logrus.DebugLevel)
	defer Logger.SetOutput(old)
	FromContext(context.Background()).WithField("k", "v").Debug("trace point")
}
