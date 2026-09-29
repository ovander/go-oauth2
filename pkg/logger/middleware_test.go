// Package logger — tests for RFC-008 correlation-ID propagation into request logs.
package logger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

// serve runs a request through RequestLoggerMiddleware and returns the captured
// log entries. Not parallel: it mutates the package-global Logger.
func serveAndCapture(t *testing.T, ctx context.Context) []*logrus.Entry {
	t.Helper()
	hook := logrustest.NewLocal(Logger)
	t.Cleanup(hook.Reset)

	prev := Logger.GetLevel()
	Logger.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() { Logger.SetLevel(prev) })

	h := RequestLoggerMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return hook.AllEntries()
}

func TestRequestLogger_IncludesCorrelationID(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.RequestIDKey, "corr-abc-123")
	entries := serveAndCapture(t, ctx)

	if len(entries) == 0 {
		t.Fatal("no log entries captured")
	}
	for _, e := range entries {
		v, ok := e.Data["correlation_id"]
		if !ok {
			t.Errorf("entry %q missing correlation_id field: %+v", e.Message, e.Data)
			continue
		}
		if v != "corr-abc-123" {
			t.Errorf("correlation_id = %v, want corr-abc-123", v)
		}
	}
}

func TestRequestLogger_OmitsCorrelationID_WhenAbsent(t *testing.T) {
	entries := serveAndCapture(t, nil) // no correlation ID in context

	if len(entries) == 0 {
		t.Fatal("no log entries captured")
	}
	for _, e := range entries {
		if _, ok := e.Data["correlation_id"]; ok {
			t.Errorf("correlation_id should be absent when not in context, got: %+v", e.Data)
		}
	}
}

func TestRequestLogger_OmitsCorrelationID_WhenEmpty(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.RequestIDKey, "")
	entries := serveAndCapture(t, ctx)

	for _, e := range entries {
		if _, ok := e.Data["correlation_id"]; ok {
			t.Errorf("empty correlation_id should not be logged, got: %+v", e.Data)
		}
	}
}
