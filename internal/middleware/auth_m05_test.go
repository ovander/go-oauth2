// Package middleware — tests for M-05: writeAuthError must produce valid JSON.
//
// M-05 fix: the previous implementation concatenated the error message directly
// into a JSON string literal.  A message containing a double-quote or backslash
// produced structurally broken JSON.  json.NewEncoder escapes all special
// characters automatically.
package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// writeAuthError — M-05: output is always valid, parseable JSON
// ---------------------------------------------------------------------------

func TestWriteAuthError_ProducesValidJSON(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	writeAuthError(w, "invalid token", http.StatusUnauthorized)

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Errorf("writeAuthError produced invalid JSON: %v\nbody: %q", err, w.Body.String())
	}
}

func TestWriteAuthError_MessageWithDoubleQuote_StillValidJSON(t *testing.T) {
	t.Parallel()
	// The old code `{"error": "` + message + `"}` would break when message
	// contained a double-quote, producing `{"error": "say "hi""}` which is
	// invalid JSON.
	tricky := `say "hello" and goodbye`
	w := httptest.NewRecorder()
	writeAuthError(w, tricky, http.StatusUnauthorized)

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Errorf("writeAuthError: message with double-quote produced invalid JSON: %v\nbody: %q",
			err, w.Body.String())
	}
	if payload["error"] != tricky {
		t.Errorf("writeAuthError: error field = %q, want %q", payload["error"], tricky)
	}
}

func TestWriteAuthError_MessageWithBackslash_StillValidJSON(t *testing.T) {
	t.Parallel()
	// The old code would produce `{"error": "C:\path"}` with an unescaped
	// backslash, which is invalid JSON (escape sequences must be complete).
	tricky := `C:\Users\admin\secret`
	w := httptest.NewRecorder()
	writeAuthError(w, tricky, http.StatusUnauthorized)

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Errorf("writeAuthError: message with backslash produced invalid JSON: %v\nbody: %q",
			err, w.Body.String())
	}
	if payload["error"] != tricky {
		t.Errorf("writeAuthError: error field = %q, want %q", payload["error"], tricky)
	}
}

func TestWriteAuthError_MessageWithNewlineAndTab_StillValidJSON(t *testing.T) {
	t.Parallel()
	tricky := "line1\nline2\ttabbed"
	w := httptest.NewRecorder()
	writeAuthError(w, tricky, http.StatusUnauthorized)

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Errorf("writeAuthError: message with newline/tab produced invalid JSON: %v\nbody: %q",
			err, w.Body.String())
	}
	if payload["error"] != tricky {
		t.Errorf("writeAuthError: error field = %q, want %q", payload["error"], tricky)
	}
}

func TestWriteAuthError_SetsContentTypeJSON(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	writeAuthError(w, "test error", http.StatusUnauthorized)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestWriteAuthError_SetsStatusCode(t *testing.T) {
	t.Parallel()
	cases := []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
	}
	for _, code := range cases {
		w := httptest.NewRecorder()
		writeAuthError(w, "err", code)
		if w.Code != code {
			t.Errorf("status = %d, want %d", w.Code, code)
		}
	}
}

func TestWriteAuthError_SetsWWWAuthenticateHeader(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	writeAuthError(w, "some error", http.StatusUnauthorized)

	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("WWW-Authenticate header must be set")
	}
}

func TestWriteAuthError_ErrorFieldPresent(t *testing.T) {
	t.Parallel()
	msg := "account is locked"
	w := httptest.NewRecorder()
	writeAuthError(w, msg, http.StatusForbidden)

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if payload["error"] != msg {
		t.Errorf("error field = %q, want %q", payload["error"], msg)
	}
}

func TestWriteAuthError_EmptyMessage_ValidJSON(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	writeAuthError(w, "", http.StatusUnauthorized)

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Errorf("writeAuthError: empty message produced invalid JSON: %v", err)
	}
}

func TestWriteAuthError_UnicodeMessage_ValidJSON(t *testing.T) {
	t.Parallel()
	// Unicode should pass through intact.
	msg := "token invalide: 认证失败 ñoño"
	w := httptest.NewRecorder()
	writeAuthError(w, msg, http.StatusUnauthorized)

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Errorf("writeAuthError: unicode message produced invalid JSON: %v\nbody: %q",
			err, w.Body.String())
	}
	if payload["error"] != msg {
		t.Errorf("error field = %q, want %q", payload["error"], msg)
	}
}
