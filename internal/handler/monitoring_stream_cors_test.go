package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStreamEvents_NoWildcardCORS verifies the SSE stream handler does not
// hard-code a wildcard Access-Control-Allow-Origin. CORS for the admin API is
// owned by the router's corsHandler middleware (H-06), which scopes the origin
// to the configured ALLOWED_ORIGINS. A wildcard on this endpoint would re-open
// the live security-telemetry stream to any origin and is invalid for the
// credentialed cross-origin fetch the monitoring SPA uses.
func TestStreamEvents_NoWildcardCORS(t *testing.T) {
	h := &MonitoringHandler{}

	// An already-cancelled context makes the streaming loop exit on its first
	// select iteration, after the response headers have been written but before
	// any database access — so a zero-value handler is safe here.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/events/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	h.StreamEvents(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatalf("stream handler must not set a wildcard Access-Control-Allow-Origin; got %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected SSE content-type text/event-stream, got %q", ct)
	}
}
