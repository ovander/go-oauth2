// Package handler — tests for NEW-04 (client authentication on the Revoke endpoint).
//
// NEW-04 fix: POST /oauth/revoke previously returned HTTP 200 for all requests
// that lacked a user Bearer token, performing no actual revocation.  It now
// authenticates client credentials (RFC 7009 §2.1) and only revokes the token
// when valid credentials are supplied.
//
// Three paths after the fix:
//
//	Path 1 — Bearer token in context (OptionalAuthMiddleware):
//	          Revoke with known userID; always return 200 (existing behaviour).
//	Path 2 — Client credentials (Basic Auth or form body):
//	          Validate via AppService.ValidateClientCredentials; if valid, revoke
//	          and return 200; if invalid, return 401.
//	Path 3 — No credentials at all:
//	          Return 200 without revoking (RFC 7009 §2.2 — token enumeration
//	          prevention).
//
// Tests:
//   - Valid client credentials (Basic Auth) → Revoke() called, 200
//   - Valid client credentials (form body) → Revoke() called, 200
//   - Invalid client credentials → 401, Revoke() NOT called
//   - No credentials at all → 200, Revoke() NOT called
//   - Bearer token path unaffected → Revoke() called with userID, 200
package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// ---------------------------------------------------------------------------
// new04 mock types
// ---------------------------------------------------------------------------

// new04AppService controls ValidateClientCredentials outcomes.
type new04AppService struct {
	validClientID     string
	validClientSecret string
}

func (m *new04AppService) GetByClientID(_ context.Context, _ string) (*model.App, error) {
	return &model.App{ID: 1, ClientID: m.validClientID}, nil
}
func (m *new04AppService) ValidateClientCredentials(_ context.Context, clientID, secret string) (*model.App, error) {
	if clientID == m.validClientID && secret == m.validClientSecret {
		return &model.App{ID: 1, ClientID: clientID}, nil
	}
	return nil, errors.New("invalid credentials")
}
func (m *new04AppService) List(_ context.Context) ([]model.App, error)           { return nil, nil }
func (m *new04AppService) GetByID(_ context.Context, _ uint) (*model.App, error) { return nil, nil }
func (m *new04AppService) GetByOwnerID(_ context.Context, _ uint) ([]model.App, error) {
	return nil, nil
}
func (m *new04AppService) Create(_ context.Context, _ dto.CreateAppRequest, _ uint) (*model.App, string, error) {
	return nil, "", errors.New("not implemented")
}
func (m *new04AppService) Update(_ context.Context, _ uint, _ dto.UpdateAppRequest) (*model.App, error) {
	return nil, errors.New("not implemented")
}
func (m *new04AppService) Delete(_ context.Context, _ uint) error { return nil }
func (m *new04AppService) RotateSecret(_ context.Context, _ uint) (*model.App, string, error) {
	return nil, "", errors.New("not implemented")
}
func (m *new04AppService) GetAllAppURLs(_ context.Context) ([]string, error) { return nil, nil }

var _ service.AppService = (*new04AppService)(nil)

// new04OAuthService counts Revoke() calls and records the userID supplied.
type new04OAuthService struct {
	revokeCalls atomic.Int64
	lastUserID  atomic.Uint64
}

func (m *new04OAuthService) Authorize(_ context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
	panic("Authorize called unexpectedly")
}
func (m *new04OAuthService) Token(_ context.Context, _ dto.TokenRequest, _, _ string) (*dto.TokenResponse, error) {
	panic("Token called unexpectedly")
}
func (m *new04OAuthService) Introspect(_ context.Context, _ string) (*dto.IntrospectResponse, error) {
	panic("Introspect called unexpectedly")
}
func (m *new04OAuthService) Revoke(_ context.Context, _ string, userID uint) error {
	m.revokeCalls.Add(1)
	m.lastUserID.Store(uint64(userID))
	return nil
}
func (m *new04OAuthService) GetUserInfo(_ context.Context, _ uint, _ string) (*dto.UserInfoResponse, error) {
	panic("GetUserInfo called unexpectedly")
}
func (m *new04OAuthService) GetOpenIDConfiguration(_ string) *dto.OpenIDConfiguration {
	return &dto.OpenIDConfiguration{}
}
func (m *new04OAuthService) GetJWKS() dto.JWKS { return dto.JWKS{} }
func (m *new04OAuthService) ValidatePasswordResetToken(_ context.Context, _ string) (string, bool) {
	return "", false
}

var _ service.OAuthService = (*new04OAuthService)(nil)

// ---------------------------------------------------------------------------
// Test factory helpers
// ---------------------------------------------------------------------------

// newNew04Handler creates an OAuthHandler wired with the injectable new04 mocks.
func newNew04Handler(appSvc service.AppService, oauthSvc service.OAuthService) *OAuthHandler {
	return &OAuthHandler{
		oauthService:    oauthSvc,
		authService:     &critAuthService{},
		appService:      appSvc,
		templateService: service.NewTemplateService(),
		issuer:          "https://auth.example.com",
		secretKey:       []byte("new04-test-secret-key-32bytes---"),
		httpsRequired:   true,
	}
}

// revokeFormRequest builds a POST /oauth/revoke form-urlencoded request.
func revokeFormRequest(token, clientID, clientSecret string) *http.Request {
	form := url.Values{}
	form.Set("token", token)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// revokeBasicAuthRequest builds a POST /oauth/revoke request with HTTP Basic
// Auth credentials.
func revokeBasicAuthRequest(token, clientID, clientSecret string) *http.Request {
	creds := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke",
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+creds)
	return req
}

// ---------------------------------------------------------------------------
// NEW-04: tests
// ---------------------------------------------------------------------------

// TestNEW04_Revoke_ValidClientCredentials_FormBody_RevokesToken verifies that
// a POST /oauth/revoke request with valid client_id + client_secret in the
// form body causes Revoke() to be called and returns HTTP 200.
func TestNEW04_Revoke_ValidClientCredentials_FormBody_RevokesToken(t *testing.T) {
	t.Parallel()
	oauthSvc := &new04OAuthService{}
	appSvc := &new04AppService{validClientID: "my-client", validClientSecret: "my-secret"}
	h := newNew04Handler(appSvc, oauthSvc)

	req := revokeFormRequest("some-token-string", "my-client", "my-secret")
	rr := httptest.NewRecorder()
	h.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("NEW-04: expected 200, got %d", rr.Code)
	}
	if oauthSvc.revokeCalls.Load() != 1 {
		t.Errorf("NEW-04: Revoke() called %d time(s), expected 1", oauthSvc.revokeCalls.Load())
	}
}

// TestNEW04_Revoke_ValidClientCredentials_BasicAuth_RevokesToken verifies that
// HTTP Basic Auth credentials are also accepted for client authentication.
func TestNEW04_Revoke_ValidClientCredentials_BasicAuth_RevokesToken(t *testing.T) {
	t.Parallel()
	oauthSvc := &new04OAuthService{}
	appSvc := &new04AppService{validClientID: "basic-client", validClientSecret: "basic-secret"}
	h := newNew04Handler(appSvc, oauthSvc)

	req := revokeBasicAuthRequest("some-token-string", "basic-client", "basic-secret")
	rr := httptest.NewRecorder()
	h.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("NEW-04: expected 200 with Basic Auth credentials, got %d", rr.Code)
	}
	if oauthSvc.revokeCalls.Load() != 1 {
		t.Errorf("NEW-04: Revoke() called %d time(s) with Basic Auth, expected 1", oauthSvc.revokeCalls.Load())
	}
}

// TestNEW04_Revoke_InvalidClientCredentials_Returns401 verifies that when a
// client_id is present but the credentials are wrong, the endpoint returns
// HTTP 401 and does NOT call Revoke().
func TestNEW04_Revoke_InvalidClientCredentials_Returns401(t *testing.T) {
	t.Parallel()
	oauthSvc := &new04OAuthService{}
	appSvc := &new04AppService{validClientID: "legit-client", validClientSecret: "correct-secret"}
	h := newNew04Handler(appSvc, oauthSvc)

	req := revokeFormRequest("some-token-string", "legit-client", "wrong-secret")
	rr := httptest.NewRecorder()
	h.Revoke(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("NEW-04: expected 401 for invalid credentials, got %d", rr.Code)
	}
	if oauthSvc.revokeCalls.Load() != 0 {
		t.Errorf("NEW-04: Revoke() must NOT be called when credentials are invalid (called %d time(s))",
			oauthSvc.revokeCalls.Load())
	}
}

// TestNEW04_Revoke_NoCredentials_Returns200_NoRevocation verifies that a
// request with no client_id and no Bearer token returns 200 (RFC 7009 token
// enumeration prevention) but does not call Revoke().
func TestNEW04_Revoke_NoCredentials_Returns200_NoRevocation(t *testing.T) {
	t.Parallel()
	oauthSvc := &new04OAuthService{}
	appSvc := &new04AppService{validClientID: "some-client", validClientSecret: "some-secret"}
	h := newNew04Handler(appSvc, oauthSvc)

	// No client_id, no secret, no Authorization header.
	req := revokeFormRequest("some-token-string", "", "")
	rr := httptest.NewRecorder()
	h.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("NEW-04: expected 200 for credential-free request (RFC 7009), got %d", rr.Code)
	}
	if oauthSvc.revokeCalls.Load() != 0 {
		t.Errorf("NEW-04: Revoke() must NOT be called when no credentials are provided (called %d time(s))",
			oauthSvc.revokeCalls.Load())
	}
}

// TestNEW04_Revoke_BearerTokenPath_StillWorks verifies that the existing
// behaviour — user authenticated via Bearer token in the request context —
// is unaffected by the NEW-04 changes.
func TestNEW04_Revoke_BearerTokenPath_StillWorks(t *testing.T) {
	t.Parallel()
	oauthSvc := &new04OAuthService{}
	appSvc := &new04AppService{validClientID: "some-client", validClientSecret: "some-secret"}
	h := newNew04Handler(appSvc, oauthSvc)

	req := revokeFormRequest("some-token-string", "", "")
	// Inject userID into the request context (simulates OptionalAuthMiddleware).
	ctx := context.WithValue(req.Context(), contextkeys.UserIDKey, uint(42))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("NEW-04: Bearer-token path returned %d, expected 200", rr.Code)
	}
	if oauthSvc.revokeCalls.Load() != 1 {
		t.Errorf("NEW-04: Revoke() should have been called once via Bearer path, got %d",
			oauthSvc.revokeCalls.Load())
	}
	if uid := oauthSvc.lastUserID.Load(); uid != 42 {
		t.Errorf("NEW-04: Revoke() called with userID=%d, expected 42", uid)
	}
}

// TestNEW04_Revoke_ClientAndBearerPresent_BearerTakesPriority verifies that
// when both a Bearer token (context) and client credentials are present, the
// Bearer token path fires first (userID is known).
func TestNEW04_Revoke_ClientAndBearerPresent_BearerTakesPriority(t *testing.T) {
	t.Parallel()
	oauthSvc := &new04OAuthService{}
	appSvc := &new04AppService{validClientID: "a-client", validClientSecret: "a-secret"}
	h := newNew04Handler(appSvc, oauthSvc)

	// Provide both client credentials and a user context.
	req := revokeFormRequest("some-token-string", "a-client", "a-secret")
	ctx := context.WithValue(req.Context(), contextkeys.UserIDKey, uint(99))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("NEW-04: expected 200, got %d", rr.Code)
	}
	// Revoke() is called once (Bearer path) with userID=99.
	if oauthSvc.revokeCalls.Load() != 1 {
		t.Errorf("NEW-04: Revoke() called %d time(s), expected exactly 1", oauthSvc.revokeCalls.Load())
	}
	if uid := oauthSvc.lastUserID.Load(); uid != 99 {
		t.Errorf("NEW-04: Bearer path expected userID=99, got %d", uid)
	}
}
