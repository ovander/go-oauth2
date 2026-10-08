package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// serveCorrelation sends one request with the given X-Correlation-ID values
// (none when nil) and returns the ID the handler saw and the response header.
func serveCorrelation(t *testing.T, values []string) (seen, header string) {
	t.Helper()
	h := CorrelationID()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = GetCorrelationID(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if values != nil {
		r.Header[http.CanonicalHeaderKey(CorrelationIDHeader)] = values
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return seen, w.Header().Get(CorrelationIDHeader)
}

func TestCorrelationID_KeepsValidIDs(t *testing.T) {
	for _, id := range []string{
		"6f1c2a4e-9b3d-4e8f-a1b2-c3d4e5f60718",
		"01J9Z3K7Q8R5T2V6W4X0Y1Z2A3",
		"req_42.retry-1",
		"trace:span:1",
		strings.Repeat("a", MaxCorrelationIDLength),
	} {
		seen, header := serveCorrelation(t, []string{id})
		if seen != id || header != id {
			t.Errorf("valid id %q: context %q, header %q", id, seen, header)
		}
	}
}

func TestCorrelationID_ReplacesInvalidIDs(t *testing.T) {
	for name, id := range map[string]string{
		"line break": "abc\r\nX-Injected: 1",
		"space":      "abc def",
		"control":    "abc\x00",
		"non-ASCII":  "é-123",
		"slash":      "a/b",
		"quote":      `a"b`,
		"too long":   strings.Repeat("a", MaxCorrelationIDLength+1),
		"json":       `{"a":1}`,
		"html":       "<script>",
		"percent":    "a%0Ab",
		"semicolon":  "a;b",
		"tab":        "a\tb",
		"backslash":  `a\b`,
	} {
		t.Run(name, func(t *testing.T) {
			seen, header := serveCorrelation(t, []string{id})
			if seen == id {
				t.Fatalf("invalid id %q was kept", id)
			}
			if _, err := uuid.Parse(seen); err != nil {
				t.Errorf("replacement %q is not a UUID", seen)
			}
			if header != seen {
				t.Errorf("response header %q, want the replacement %q", header, seen)
			}
		})
	}
}

func TestCorrelationID_GeneratesWhenAbsent(t *testing.T) {
	seen, header := serveCorrelation(t, nil)
	if _, err := uuid.Parse(seen); err != nil || header != seen {
		t.Errorf("context %q, header %q: want the same generated UUID", seen, header)
	}
}
