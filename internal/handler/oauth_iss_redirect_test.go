package handler

import (
	"net/url"
	"testing"
)

// buildAuthzRedirect appends code, state, and the RFC 9207 iss parameter, and
// preserves any existing query parameters on the redirect URI.
func TestBuildAuthzRedirect_IncludesIssAndState(t *testing.T) {
	u, _ := url.Parse("https://client.example.com/callback?foo=bar")
	got := buildAuthzRedirect(u, "the-code", "the-state", "https://auth.example.com")

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v", err)
	}
	q := parsed.Query()
	if q.Get("code") != "the-code" {
		t.Errorf("code = %q, want the-code", q.Get("code"))
	}
	if q.Get("state") != "the-state" {
		t.Errorf("state = %q, want the-state", q.Get("state"))
	}
	if q.Get("iss") != "https://auth.example.com" {
		t.Errorf("iss = %q, want the issuer (RFC 9207)", q.Get("iss"))
	}
	if q.Get("foo") != "bar" {
		t.Errorf("pre-existing query param dropped: foo = %q", q.Get("foo"))
	}
}

// State and iss are omitted/included correctly when empty.
func TestBuildAuthzRedirect_OmitsEmptyStateAndIssuer(t *testing.T) {
	u, _ := url.Parse("https://client.example.com/cb")
	got := buildAuthzRedirect(u, "c", "", "")

	q, _ := url.Parse(got)
	if q.Query().Has("state") {
		t.Error("empty state must be omitted")
	}
	if q.Query().Has("iss") {
		t.Error("empty issuer must omit iss")
	}
	if q.Query().Get("code") != "c" {
		t.Error("code must always be present")
	}
}
