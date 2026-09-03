package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// P4-3: an over-size body must surface as *http.MaxBytesError to the handler
// (which the JSON handlers turn into 400 "invalid JSON"), never be read whole.
func TestMaxRequestBody_RejectsOversizeBody(t *testing.T) {
	var gotErr error
	var read int
	h := MaxRequestBody(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		read, gotErr = len(b), err
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(strings.Repeat("x", 1000))))

	var mbe *http.MaxBytesError
	if !errors.As(gotErr, &mbe) {
		t.Fatalf("err = %v, want *http.MaxBytesError", gotErr)
	}
	if read > 16 {
		t.Fatalf("handler read %d bytes past the cap", read)
	}
}

func TestMaxRequestBody_AllowsBodiesWithinLimit(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"email": "a@example.com", "password": "pw"})
	var decoded map[string]string
	h := MaxRequestBody(DefaultMaxRequestBody)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body)))
	if decoded["email"] != "a@example.com" {
		t.Fatalf("decoded = %v", decoded)
	}
}

func TestMaxRequestBody_JSONDecoderReportsInvalidBody(t *testing.T) {
	// What the real handlers do: decode straight from r.Body and map any error
	// to 400. Make sure the cap trips before the decoder materialises the string.
	h := MaxRequestBody(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v struct{ Email string }
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"email":"`+strings.Repeat("a", 10_000)+`"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rr.Code)
	}
}
