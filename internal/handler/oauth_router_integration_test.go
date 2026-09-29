// Package handler — Phase 1 integration tests (docs/program/TEST-STRATEGY.md).
//
// These drive the OAuth/OIDC endpoints through a real chi router with the real
// middleware stack (JSONContentType / NoCacheHeaders / DPoP), exercising the
// HTTP wiring — routing, middleware order, response headers, content type,
// method handling, error mapping — that unit tests of handler methods can't see.
// The service is a configurable fake so the focus stays on the HTTP layer (the
// service logic is covered by the service-package unit tests).
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
)

// okAppSvc satisfies service.AppService (via the embedded mock) but accepts any
// client credentials — the integration tests focus on HTTP wiring, not auth
// policy (which the service-package unit tests cover).
type okAppSvc struct{ *mockAppService }

func (okAppSvc) ValidateClientCredentials(_ context.Context, clientID, _ string) (*model.App, error) {
	return &model.App{ClientID: clientID}, nil
}

// fakeOAuthSvc is a configurable full implementation of service.OAuthService.
type fakeOAuthSvc struct {
	tokenResp  *dto.TokenResponse
	tokenErr   error
	introspect *dto.IntrospectResponse
	discovery  *dto.OpenIDConfiguration
	jwks       dto.JWKS
	gotReq     dto.TokenRequest // captures the last Token() request (for assertions)
}

func (f *fakeOAuthSvc) Authorize(_ context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
	return "code", nil
}
func (f *fakeOAuthSvc) Token(_ context.Context, req dto.TokenRequest, _, _ string) (*dto.TokenResponse, error) {
	f.gotReq = req
	return f.tokenResp, f.tokenErr
}
func (f *fakeOAuthSvc) ExchangeToken(_ context.Context, _ url.Values, _, _ string) (*dto.TokenResponse, error) {
	return f.tokenResp, f.tokenErr
}
func (f *fakeOAuthSvc) Introspect(_ context.Context, _ string, _ string) (*dto.IntrospectResponse, error) {
	return f.introspect, nil
}
func (f *fakeOAuthSvc) Revoke(_ context.Context, _ string, _ uint, _ string) error { return nil }
func (f *fakeOAuthSvc) GetUserInfo(_ context.Context, _ uint, _ string) (*dto.UserInfoResponse, error) {
	return &dto.UserInfoResponse{}, nil
}
func (f *fakeOAuthSvc) GetOpenIDConfiguration(_ string) *dto.OpenIDConfiguration { return f.discovery }
func (f *fakeOAuthSvc) GetJWKS() dto.JWKS                                        { return f.jwks }
func (f *fakeOAuthSvc) ValidatePasswordResetToken(_ context.Context, _ string) (string, bool) {
	return "", false
}

// buildOAuthTestRouter mounts the no-auth OAuth/OIDC endpoints with the same
// middleware the production router uses (internal/http/router.go).
func buildOAuthTestRouter(svc *fakeOAuthSvc) http.Handler {
	h := &OAuthHandler{oauthService: svc, appService: okAppSvc{&mockAppService{}}, issuer: "https://auth.example.com"}
	r := chi.NewRouter()
	r.With(middleware.JSONContentType()).Get("/.well-known/openid-configuration", h.OpenIDConfiguration)
	r.With(middleware.JSONContentType()).Get("/.well-known/jwks.json", h.JWKS)
	r.Route("/oauth", func(r chi.Router) {
		r.With(middleware.JSONContentType(), middleware.NoCacheHeaders(),
			middleware.DPoP(nil, "off", "https://auth.example.com")).
			Post("/token", h.Token)
		r.With(middleware.JSONContentType()).Post("/introspect", h.Introspect)
	})
	return r
}

func TestIntegration_Discovery(t *testing.T) {
	svc := &fakeOAuthSvc{discovery: &dto.OpenIDConfiguration{
		Issuer:        "https://auth.example.com",
		TokenEndpoint: "https://auth.example.com/oauth/token",
	}}
	r := buildOAuthTestRouter(svc)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got dto.OpenIDConfiguration
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("discovery body not JSON: %v", err)
	}
	if got.Issuer != "https://auth.example.com" {
		t.Errorf("issuer = %q", got.Issuer)
	}
}

func TestIntegration_JWKS(t *testing.T) {
	svc := &fakeOAuthSvc{jwks: dto.JWKS{Keys: []dto.JWK{{Kty: "RSA", Kid: "k1", Use: "sig", Alg: "RS256"}}}}
	r := buildOAuthTestRouter(svc)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got dto.JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || len(got.Keys) != 1 {
		t.Fatalf("jwks body = %s (err %v)", rr.Body.String(), err)
	}
}

func TestIntegration_TokenEndpoint_SuccessAndNoStore(t *testing.T) {
	svc := &fakeOAuthSvc{tokenResp: &dto.TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900}}
	r := buildOAuthTestRouter(svc)

	body := strings.NewReader("grant_type=client_credentials&scope=api")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	// no-store must be applied through the real handler/middleware stack (#142/#143).
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		t.Errorf("token response not no-store: Cache-Control=%q Pragma=%q",
			rr.Header().Get("Cache-Control"), rr.Header().Get("Pragma"))
	}
	var tok dto.TokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil || tok.AccessToken != "at" {
		t.Fatalf("token body = %s (err %v)", rr.Body.String(), err)
	}
}

func TestIntegration_TokenEndpoint_WrongMethod(t *testing.T) {
	r := buildOAuthTestRouter(&fakeOAuthSvc{})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oauth/token", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /oauth/token = %d, want 405", rr.Code)
	}
}

func TestIntegration_Introspect_NoStore(t *testing.T) {
	svc := &fakeOAuthSvc{introspect: &dto.IntrospectResponse{Active: true, Sub: "42", Scope: "api"}}
	r := buildOAuthTestRouter(svc)

	body := strings.NewReader("token=abc&client_id=c&client_secret=s")
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("introspection must be no-store (RFC 7662 §4), got %q", rr.Header().Get("Cache-Control"))
	}
	var ir dto.IntrospectResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &ir); err != nil || !ir.Active {
		t.Fatalf("introspect body = %s (err %v)", rr.Body.String(), err)
	}
}

// Even the unauthenticated 401 path must carry no-store (setNoStore runs first).
func TestIntegration_Introspect_Unauthenticated_NoStoreAnd401(t *testing.T) {
	r := buildOAuthTestRouter(&fakeOAuthSvc{})
	body := strings.NewReader("token=abc") // no client credentials
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("even the 401 introspect path must be no-store, got %q", rr.Header().Get("Cache-Control"))
	}
}

func TestIntegration_UnknownRoute_404(t *testing.T) {
	r := buildOAuthTestRouter(&fakeOAuthSvc{})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oauth/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("unknown route = %d, want 404", rr.Code)
	}
}
