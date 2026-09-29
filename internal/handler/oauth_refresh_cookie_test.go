// Package handler — tests for the first-party admin-console refresh-token
// cookie channel (Tier-0 admin session hardening, PR2).
//
// When ADMIN_CONSOLE_CLIENT_ID is configured, the token endpoint delivers that
// client's refresh token as an HttpOnly; Secure; SameSite=Strict cookie instead
// of in the JSON body (XSS-safe silent refresh), reads it back from the cookie
// on refresh, and logout clears it. The channel is inert when unconfigured.
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
)

const adminClientID = "admin-console"

// newCookieOAuthHandler builds an OAuthHandler over a fake service; when
// clientID is non-empty the refresh-cookie channel is enabled for it.
func newCookieOAuthHandler(svc *fakeOAuthSvc, clientID string) *OAuthHandler {
	h := &OAuthHandler{oauthService: svc, appService: okAppSvc{&mockAppService{}}, issuer: "https://auth.example.com"}
	if clientID != "" {
		h.SetRefreshCookie(clientID, 7*24*time.Hour, true)
	}
	return h
}

// postToken drives h.Token with a form body and optional cookies.
func postToken(h *OAuthHandler, form string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.Token(rr, r)
	return rr
}

func findCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range (&http.Response{Header: rr.Header()}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func decodeToken(t *testing.T, rr *httptest.ResponseRecorder) dto.TokenResponse {
	t.Helper()
	var resp dto.TokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token response: %v (body=%s)", err, rr.Body.String())
	}
	return resp
}

// TestRefreshCookie_AdminClient_SetAndStrippedFromBody: a successful grant for
// the admin client sets the refresh cookie with the right flags and removes the
// refresh token from the JSON body (cookie-only, XSS-safe).
func TestRefreshCookie_AdminClient_SetAndStrippedFromBody(t *testing.T) {
	svc := &fakeOAuthSvc{tokenResp: &dto.TokenResponse{AccessToken: "at", RefreshToken: "rt-new", TokenType: "Bearer", ExpiresIn: 900}}
	h := newCookieOAuthHandler(svc, adminClientID)

	rr := postToken(h, "grant_type=authorization_code&code=abc&code_verifier=v&client_id="+adminClientID)

	ck := findCookie(rr, "refresh_token")
	if ck == nil {
		t.Fatal("expected a refresh_token cookie to be set for the admin client")
	}
	if ck.Value != "rt-new" {
		t.Errorf("cookie value = %q, want the rotated refresh token", ck.Value)
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags wrong: HttpOnly=%v Secure=%v SameSite=%v", ck.HttpOnly, ck.Secure, ck.SameSite)
	}
	if ck.Path != "/oauth/token" {
		t.Errorf("cookie path = %q, want /oauth/token", ck.Path)
	}
	if ck.MaxAge <= 0 {
		t.Errorf("cookie Max-Age = %d, want the refresh TTL", ck.MaxAge)
	}
	if got := decodeToken(t, rr); got.RefreshToken != "" {
		t.Errorf("refresh token must NOT appear in the JSON body for the admin client, got %q", got.RefreshToken)
	}
}

// TestRefreshCookie_AdminClient_ReadFromCookie: on refresh, when no form
// refresh_token is supplied, the handler injects the cookie value into the
// request so the hardened grant (rotation/replay/DPoP) runs over it.
func TestRefreshCookie_AdminClient_ReadFromCookie(t *testing.T) {
	svc := &fakeOAuthSvc{tokenResp: &dto.TokenResponse{AccessToken: "at", RefreshToken: "rt-new", TokenType: "Bearer"}}
	h := newCookieOAuthHandler(svc, adminClientID)

	postToken(h, "grant_type=refresh_token&client_id="+adminClientID,
		&http.Cookie{Name: "refresh_token", Value: "rt-incoming"})

	if svc.gotReq.RefreshToken != "rt-incoming" {
		t.Errorf("service received refresh_token %q, want the cookie value rt-incoming", svc.gotReq.RefreshToken)
	}
}

// TestRefreshCookie_ExplicitFormValueWins: an explicit form refresh_token is not
// overridden by the cookie.
func TestRefreshCookie_ExplicitFormValueWins(t *testing.T) {
	svc := &fakeOAuthSvc{tokenResp: &dto.TokenResponse{AccessToken: "at", TokenType: "Bearer"}}
	h := newCookieOAuthHandler(svc, adminClientID)

	postToken(h, "grant_type=refresh_token&client_id="+adminClientID+"&refresh_token=rt-form",
		&http.Cookie{Name: "refresh_token", Value: "rt-cookie"})

	if svc.gotReq.RefreshToken != "rt-form" {
		t.Errorf("explicit form value should win, got %q", svc.gotReq.RefreshToken)
	}
}

// TestRefreshCookie_NonAdminClient_NoCookie: a different client gets the refresh
// token in the body and no cookie.
func TestRefreshCookie_NonAdminClient_NoCookie(t *testing.T) {
	svc := &fakeOAuthSvc{tokenResp: &dto.TokenResponse{AccessToken: "at", RefreshToken: "rt-new", TokenType: "Bearer"}}
	h := newCookieOAuthHandler(svc, adminClientID)

	rr := postToken(h, "grant_type=authorization_code&code=abc&code_verifier=v&client_id=some-other-app")

	if findCookie(rr, "refresh_token") != nil {
		t.Error("non-admin client must not receive a refresh cookie")
	}
	if got := decodeToken(t, rr); got.RefreshToken != "rt-new" {
		t.Errorf("non-admin client should keep the refresh token in the body, got %q", got.RefreshToken)
	}
}

// TestRefreshCookie_Disabled_NoCookie: with the channel unconfigured, even the
// admin client behaves exactly as before (token in body, no cookie).
func TestRefreshCookie_Disabled_NoCookie(t *testing.T) {
	svc := &fakeOAuthSvc{tokenResp: &dto.TokenResponse{AccessToken: "at", RefreshToken: "rt-new", TokenType: "Bearer"}}
	h := newCookieOAuthHandler(svc, "") // disabled

	rr := postToken(h, "grant_type=authorization_code&code=abc&code_verifier=v&client_id="+adminClientID)

	if findCookie(rr, "refresh_token") != nil {
		t.Error("no cookie should be set when the channel is disabled")
	}
	if got := decodeToken(t, rr); got.RefreshToken != "rt-new" {
		t.Errorf("disabled channel should keep the refresh token in the body, got %q", got.RefreshToken)
	}
}

// TestRefreshCookie_LogoutClearsCookie: logout expires the refresh cookie when
// the channel is enabled.
func TestRefreshCookie_LogoutClearsCookie(t *testing.T) {
	h := NewAuthHandler(&med03AuthService{}, &med03UserService{}, &med03EmailService{}, "production", "https://auth.example.com")
	h.SetRefreshCookie(true, true)

	r := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	r = r.WithContext(context.WithValue(r.Context(), contextkeys.UserIDKey, uint(7)))
	rr := httptest.NewRecorder()
	h.Logout(rr, r)

	ck := findCookie(rr, "refresh_token")
	if ck == nil {
		t.Fatal("logout should emit a Set-Cookie clearing the refresh cookie")
	}
	if ck.MaxAge >= 0 || ck.Value != "" {
		t.Errorf("logout cookie should be expired (MaxAge<0, empty value), got MaxAge=%d value=%q", ck.MaxAge, ck.Value)
	}
	if ck.Path != "/oauth/token" {
		t.Errorf("clearing cookie path = %q, want /oauth/token (must match the set cookie)", ck.Path)
	}
}
