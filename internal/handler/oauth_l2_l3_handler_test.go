// Package handler — handler-level wiring tests for L2 (introspection
// audience binding) and L3 (revoke ownership check), Socrate suite audit
// remediation.
//
// The audience/ownership logic itself lives in oauthService and is exercised
// directly in internal/service/oauth_l2_l3_audience_test.go. These tests
// instead guard the handler wiring: that POST /oauth/introspect and
// POST /oauth/revoke pass the client that just authenticated (not an
// unauthenticated or attacker-controlled value) as the requestingClientID
// argument to the service layer.
package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

// l2l3OAuthService captures the arguments Introspect/Revoke were called
// with; all other methods panic (unused by these tests).
type l2l3OAuthService struct {
	introspectCalledWith string
	revokeCalledWith     string
	revokeCallCount      int
}

func (m *l2l3OAuthService) Authorize(_ context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
	panic("Authorize called unexpectedly")
}
func (m *l2l3OAuthService) Token(_ context.Context, _ dto.TokenRequest, _, _ string) (*dto.TokenResponse, error) {
	panic("Token called unexpectedly")
}
func (m *l2l3OAuthService) ExchangeToken(_ context.Context, _ url.Values, _, _ string) (*dto.TokenResponse, error) {
	panic("ExchangeToken called unexpectedly")
}
func (m *l2l3OAuthService) Introspect(_ context.Context, _ string, requestingClientID string) (*dto.IntrospectResponse, error) {
	m.introspectCalledWith = requestingClientID
	return &dto.IntrospectResponse{Active: true}, nil
}
func (m *l2l3OAuthService) Revoke(_ context.Context, _ string, _ uint, requestingClientID string) error {
	m.revokeCallCount++
	m.revokeCalledWith = requestingClientID
	return nil
}
func (m *l2l3OAuthService) GetUserInfo(_ context.Context, _ uint, _ string) (*dto.UserInfoResponse, error) {
	panic("GetUserInfo called unexpectedly")
}
func (m *l2l3OAuthService) GetOpenIDConfiguration(_ string) *dto.OpenIDConfiguration {
	return &dto.OpenIDConfiguration{}
}
func (m *l2l3OAuthService) GetJWKS() dto.JWKS { return dto.JWKS{} }
func (m *l2l3OAuthService) ValidatePasswordResetToken(_ context.Context, _ string) (string, bool) {
	return "", false
}

// l2l3AppService accepts exactly one client_id/secret pair.
type l2l3AppService struct {
	validClientID     string
	validClientSecret string
}

func (m *l2l3AppService) GetByClientID(_ context.Context, clientID string) (*model.App, error) {
	return &model.App{ID: 1, ClientID: clientID}, nil
}
func (m *l2l3AppService) ValidateClientCredentials(_ context.Context, clientID, secret string) (*model.App, error) {
	if clientID == m.validClientID && secret == m.validClientSecret {
		return &model.App{ID: 1, ClientID: clientID}, nil
	}
	return nil, errors.New("invalid credentials")
}
func (m *l2l3AppService) List(_ context.Context) ([]model.App, error)           { return nil, nil }
func (m *l2l3AppService) GetByID(_ context.Context, _ uint) (*model.App, error) { return nil, nil }
func (m *l2l3AppService) GetByOwnerID(_ context.Context, _ uint) ([]model.App, error) {
	return nil, nil
}
func (m *l2l3AppService) Create(_ context.Context, _ dto.CreateAppRequest, _ uint) (*model.App, string, error) {
	return nil, "", errors.New("not implemented")
}
func (m *l2l3AppService) Update(_ context.Context, _ uint, _ dto.UpdateAppRequest) (*model.App, error) {
	return nil, errors.New("not implemented")
}
func (m *l2l3AppService) Delete(_ context.Context, _ uint) error { return nil }
func (m *l2l3AppService) RotateSecret(_ context.Context, _ uint) (*model.App, string, error) {
	return nil, "", errors.New("not implemented")
}
func (m *l2l3AppService) GetAllAppURLs(_ context.Context) ([]string, error) { return nil, nil }

func newL2L3Handler(appSvc *l2l3AppService, oauthSvc *l2l3OAuthService) *OAuthHandler {
	return &OAuthHandler{
		oauthService:  oauthSvc,
		appService:    appSvc,
		issuer:        "https://auth.example.com",
		secretKey:     []byte("l2l3-test-secret-key-32-bytes---"),
		httpsRequired: true,
	}
}

// ---------------------------------------------------------------------------
// L2: POST /oauth/introspect passes the authenticated client's own client_id
// ---------------------------------------------------------------------------

func TestL2_Introspect_HandlerPassesAuthenticatedClientID(t *testing.T) {
	appSvc := &l2l3AppService{validClientID: "my-client", validClientSecret: "my-secret"}
	oauthSvc := &l2l3OAuthService{}
	h := newL2L3Handler(appSvc, oauthSvc)

	form := url.Values{
		"token":         {"some-opaque-token"},
		"client_id":     {"my-client"},
		"client_secret": {"my-secret"},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Introspect(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if oauthSvc.introspectCalledWith != "my-client" {
		t.Errorf("L2: Introspect handler passed requestingClientID=%q, want %q",
			oauthSvc.introspectCalledWith, "my-client")
	}
}

// ---------------------------------------------------------------------------
// L3: POST /oauth/revoke passes the authenticated client's own client_id on
// the client-credential path, and an empty string on the user-Bearer path.
// ---------------------------------------------------------------------------

func TestL3_Revoke_ClientCredentialPath_PassesAuthenticatedClientID(t *testing.T) {
	appSvc := &l2l3AppService{validClientID: "my-client", validClientSecret: "my-secret"}
	oauthSvc := &l2l3OAuthService{}
	h := newL2L3Handler(appSvc, oauthSvc)

	form := url.Values{
		"token":         {"some-token-value"},
		"client_id":     {"my-client"},
		"client_secret": {"my-secret"},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Revoke(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if oauthSvc.revokeCallCount != 1 {
		t.Fatalf("Revoke() called %d time(s), want 1", oauthSvc.revokeCallCount)
	}
	if oauthSvc.revokeCalledWith != "my-client" {
		t.Errorf("L3: Revoke handler passed requestingClientID=%q, want %q",
			oauthSvc.revokeCalledWith, "my-client")
	}
}

func TestL3_Revoke_UserBearerPath_PassesEmptyClientID(t *testing.T) {
	appSvc := &l2l3AppService{validClientID: "my-client", validClientSecret: "my-secret"}
	oauthSvc := &l2l3OAuthService{}
	h := newL2L3Handler(appSvc, oauthSvc)

	form := url.Values{"token": {"some-token-value"}}
	r := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Simulate an authenticated end-user (Bearer token), not a client.
	ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, uint(7))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Revoke(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if oauthSvc.revokeCallCount != 1 {
		t.Fatalf("Revoke() called %d time(s), want 1", oauthSvc.revokeCallCount)
	}
	if oauthSvc.revokeCalledWith != "" {
		t.Errorf("L3: user-Bearer revoke path must pass requestingClientID=\"\" (ownership check does not apply), got %q",
			oauthSvc.revokeCalledWith)
	}
}
