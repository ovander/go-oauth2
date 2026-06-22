package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
)

// jwksOAuthService embeds the panic-by-default mock and returns an empty JWKS so
// the JWKS handler's caching headers can be asserted in isolation.
type jwksOAuthService struct {
	mockOAuthService
}

func (*jwksOAuthService) GetJWKS() dto.JWKS { return dto.JWKS{} }

func TestJWKS_CacheControlEnabled(t *testing.T) {
	h := &OAuthHandler{oauthService: &jwksOAuthService{}}
	h.SetJWKSCacheMaxAge(300)

	rr := httptest.NewRecorder()
	h.JWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q, want \"public, max-age=300\"", got)
	}
}

func TestJWKS_CacheControlDisabledWhenZero(t *testing.T) {
	h := &OAuthHandler{oauthService: &jwksOAuthService{}}
	h.SetJWKSCacheMaxAge(0)

	rr := httptest.NewRecorder()
	h.JWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want \"no-store\"", got)
	}
}

func TestJWKS_SetsETagAndBody(t *testing.T) {
	h := &OAuthHandler{oauthService: &jwksOAuthService{}}

	rr := httptest.NewRecorder()
	h.JWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatal("expected an ETag header")
	}
	if rr.Body.Len() == 0 {
		t.Fatal("expected a JWKS body on a 200")
	}
}

func TestJWKS_NotModifiedOnMatchingIfNoneMatch(t *testing.T) {
	h := &OAuthHandler{oauthService: &jwksOAuthService{}}

	// First request to learn the current ETag.
	first := httptest.NewRecorder()
	h.JWKS(first, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	etag := first.Header().Get("ETag")

	// Conditional request with the same ETag -> 304, no body.
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	req.Header.Set("If-None-Match", etag)
	rr := httptest.NewRecorder()
	h.JWKS(rr, req)

	if rr.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("304 must have no body, got %d bytes", rr.Body.Len())
	}
	if rr.Header().Get("ETag") != etag {
		t.Fatal("304 should still carry the ETag")
	}
}

func TestJWKS_ServesBodyOnStaleIfNoneMatch(t *testing.T) {
	h := &OAuthHandler{oauthService: &jwksOAuthService{}}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	req.Header.Set("If-None-Match", `"stale-etag"`)
	rr := httptest.NewRecorder()
	h.JWKS(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for a non-matching ETag, got %d", rr.Code)
	}
}

func TestIfNoneMatchSatisfied(t *testing.T) {
	etag := `"abc123"`
	cases := []struct {
		header string
		want   bool
	}{
		{"", false},
		{"*", true},
		{`"abc123"`, true},
		{`"other", "abc123"`, true},
		{`W/"abc123"`, true},
		{`"nope"`, false},
	}
	for _, c := range cases {
		if got := ifNoneMatchSatisfied(c.header, etag); got != c.want {
			t.Errorf("ifNoneMatchSatisfied(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}
