// Package handler — white-box tests for the OAuthHandler security fixes.
// White-box access is required to test the unexported extractClientIDFromTokenHint helper.
package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// ---------------------------------------------------------------------------
// Minimal mocks
// ---------------------------------------------------------------------------

// mockAppService stubs only GetByClientID; all other methods panic if called
// so that tests explicitly opt-in to any method they need.
type mockAppService struct {
	getByClientID func(ctx context.Context, clientID string) (*model.App, error)
}

func (m *mockAppService) GetByClientID(ctx context.Context, clientID string) (*model.App, error) {
	if m.getByClientID != nil {
		return m.getByClientID(ctx, clientID)
	}
	panic("GetByClientID called unexpectedly")
}

func (m *mockAppService) List(ctx context.Context) ([]model.App, error) { panic("not implemented") }
func (m *mockAppService) GetByID(ctx context.Context, id uint) (*model.App, error) {
	panic("not implemented")
}
func (m *mockAppService) GetByOwnerID(ctx context.Context, ownerID uint) ([]model.App, error) {
	panic("not implemented")
}
func (m *mockAppService) Create(ctx context.Context, req dto.CreateAppRequest, ownerID uint) (*model.App, string, error) {
	panic("not implemented")
}
func (m *mockAppService) Update(ctx context.Context, id uint, req dto.UpdateAppRequest) (*model.App, error) {
	panic("not implemented")
}
func (m *mockAppService) Delete(ctx context.Context, id uint) error { panic("not implemented") }
func (m *mockAppService) RotateSecret(ctx context.Context, id uint) (*model.App, string, error) {
	panic("not implemented")
}
func (m *mockAppService) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*model.App, error) {
	panic("not implemented")
}
func (m *mockAppService) GetAllAppURLs(ctx context.Context) ([]string, error) {
	panic("not implemented")
}

// mockOAuthService stubs only Revoke; all other methods panic.
type mockOAuthService struct {
	revoke func(ctx context.Context, token string, userID uint) error
}

func (m *mockOAuthService) Revoke(ctx context.Context, token string, userID uint) error {
	if m.revoke != nil {
		return m.revoke(ctx, token, userID)
	}
	return nil // default: success
}

func (m *mockOAuthService) Authorize(_ context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
	panic("not implemented")
}
func (m *mockOAuthService) Token(_ context.Context, _ dto.TokenRequest, _, _ string) (*dto.TokenResponse, error) {
	panic("not implemented")
}
func (m *mockOAuthService) Introspect(_ context.Context, _ string) (*dto.IntrospectResponse, error) {
	panic("not implemented")
}
func (m *mockOAuthService) GetUserInfo(_ context.Context, _ uint, _ string) (*dto.UserInfoResponse, error) {
	panic("not implemented")
}
func (m *mockOAuthService) GetOpenIDConfiguration(_ string) *dto.OpenIDConfiguration {
	panic("not implemented")
}
func (m *mockOAuthService) ExchangeToken(_ context.Context, _ url.Values, _, _ string) (*dto.TokenResponse, error) {
	panic("not implemented")
}
func (m *mockOAuthService) GetJWKS() dto.JWKS { panic("not implemented") }
func (m *mockOAuthService) ValidatePasswordResetToken(_ context.Context, _ string) (string, bool) {
	panic("not implemented")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestEndSessionHandler returns an OAuthHandler with the supplied mocks.
// authService and templateService are not exercised by EndSession.
func newTestEndSessionHandler(appSvc service.AppService, oauthSvc service.OAuthService) *OAuthHandler {
	return &OAuthHandler{
		appService:   appSvc,
		oauthService: oauthSvc,
		issuer:       "https://auth.example.com",
	}
}

// buildJWTPayload encodes a map as a base64url JWT payload fragment (header.payload.sig).
func buildJWTPayload(claims map[string]interface{}) string {
	raw, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return "eyJhbGciOiJSUzI1NiJ9." + payload + ".fakesig"
}

// ---------------------------------------------------------------------------
// extractClientIDFromTokenHint
// ---------------------------------------------------------------------------

func TestExtractClientIDFromTokenHint_ValidToken(t *testing.T) {
	tests := []struct {
		name   string
		aud    interface{}
		wantID string
	}{
		{
			name:   "string audience",
			aud:    "my-client",
			wantID: "my-client",
		},
		{
			name:   "array audience — first element returned",
			aud:    []string{"first-client", "second-client"},
			wantID: "first-client",
		},
		{
			name:   "single-element array",
			aud:    []string{"only-client"},
			wantID: "only-client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := buildJWTPayload(map[string]interface{}{
				"sub": "42",
				"aud": tt.aud,
				"iat": time.Now().Unix(),
			})
			got := extractClientIDFromTokenHint(token)
			if got != tt.wantID {
				t.Errorf("extractClientIDFromTokenHint() = %q, want %q", got, tt.wantID)
			}
		})
	}
}

func TestExtractClientIDFromTokenHint_InvalidOrMissingAudience(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty string",
			token: "",
		},
		{
			name:  "not a JWT (no dots)",
			token: "notajwt",
		},
		{
			name:  "only two parts",
			token: "header.payload",
		},
		{
			name:  "invalid base64 payload",
			token: "eyJhbGciOiJSUzI1NiJ9.!!!invalid!!!.sig",
		},
		{
			name: "valid JWT but no aud claim",
			token: buildJWTPayload(map[string]interface{}{
				"sub": "42",
			}),
		},
		{
			name: "empty array audience",
			token: buildJWTPayload(map[string]interface{}{
				"aud": []string{},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractClientIDFromTokenHint(tt.token)
			if got != "" {
				t.Errorf("extractClientIDFromTokenHint() = %q, want empty string", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EndSession — C-01 open redirect fix
// ---------------------------------------------------------------------------

func TestEndSession_NoRedirectURI_ReturnsJSON(t *testing.T) {
	// Without a post_logout_redirect_uri the handler must return a JSON success
	// response and must not attempt any redirect.
	h := newTestEndSessionHandler(&mockAppService{}, &mockOAuthService{})

	r := httptest.NewRequest(http.MethodGet, "/oauth/logout", nil)
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestEndSession_RegisteredURI_WithExplicitClientID_Redirects(t *testing.T) {
	// Happy path: client_id provided explicitly, URI is registered → redirect.
	registeredURI := "https://app.example.com/logout"
	appSvc := &mockAppService{
		getByClientID: func(_ context.Context, clientID string) (*model.App, error) {
			if clientID != "good-client" {
				return nil, fmt.Errorf("not found")
			}
			return &model.App{
				ClientID:     "good-client",
				RedirectURIs: model.StringArray{registeredURI},
			}, nil
		},
	}
	h := newTestEndSessionHandler(appSvc, &mockOAuthService{})

	target := "/oauth/logout?client_id=good-client&post_logout_redirect_uri=" +
		url.QueryEscape(registeredURI)
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect)", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != registeredURI {
		t.Errorf("Location = %q, want %q", loc, registeredURI)
	}
}

func TestEndSession_RegisteredURIWithState_StateAppendedToRedirect(t *testing.T) {
	// state parameter must be forwarded to the redirect target.
	registeredURI := "https://app.example.com/post-logout"
	appSvc := &mockAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) {
			return &model.App{RedirectURIs: model.StringArray{registeredURI}}, nil
		},
	}
	h := newTestEndSessionHandler(appSvc, &mockOAuthService{})

	target := "/oauth/logout?client_id=any&state=abc123&post_logout_redirect_uri=" +
		url.QueryEscape(registeredURI)
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location %q is not a valid URL: %v", loc, err)
	}
	if parsed.Query().Get("state") != "abc123" {
		t.Errorf("state in redirect = %q, want %q", parsed.Query().Get("state"), "abc123")
	}
}

func TestEndSession_UnregisteredURI_DoesNotRedirect(t *testing.T) {
	// C-01 core test: an attacker-controlled URI that is NOT registered for the
	// client must be silently dropped.  The handler must fall through to the
	// JSON response rather than redirecting the user to an arbitrary host.
	appSvc := &mockAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) {
			return &model.App{
				ClientID:     "legit-client",
				RedirectURIs: model.StringArray{"https://legit.example.com/logout"},
			}, nil
		},
	}
	h := newTestEndSessionHandler(appSvc, &mockOAuthService{})

	maliciousURI := "https://evil.example.com/steal-tokens"
	target := "/oauth/logout?client_id=legit-client&post_logout_redirect_uri=" +
		url.QueryEscape(maliciousURI)
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code == http.StatusFound {
		t.Errorf("handler redirected to unregistered URI %q (open redirect not fixed)", w.Header().Get("Location"))
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (JSON fallback)", w.Code)
	}
}

func TestEndSession_DangerousScheme_DoesNotRedirect(t *testing.T) {
	// javascript: and data: URIs must never be honoured.
	appSvc := &mockAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) {
			// Return an app that claims javascript: as a redirect URI to ensure
			// ValidateRedirectURI blocks it even when "registered".
			return &model.App{
				ClientID:     "bad-client",
				RedirectURIs: model.StringArray{"javascript:alert(1)"},
			}, nil
		},
	}
	h := newTestEndSessionHandler(appSvc, &mockOAuthService{})

	dangerousURIs := []string{
		"javascript:alert(document.cookie)",
		"data:text/html,<script>alert(1)</script>",
	}

	for _, uri := range dangerousURIs {
		t.Run(uri, func(t *testing.T) {
			target := "/oauth/logout?client_id=bad-client&post_logout_redirect_uri=" +
				url.QueryEscape(uri)
			r := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			h.EndSession(w, r)

			if w.Code == http.StatusFound {
				t.Errorf("handler redirected to dangerous URI %q", uri)
			}
		})
	}
}

func TestEndSession_NoClientID_NoRedirect(t *testing.T) {
	// Without a client_id (and no id_token_hint), the handler cannot validate
	// the redirect URI and must fall through to the JSON response.
	h := newTestEndSessionHandler(&mockAppService{}, &mockOAuthService{})

	target := "/oauth/logout?post_logout_redirect_uri=" +
		url.QueryEscape("https://attacker.example.com/steal")
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code == http.StatusFound {
		t.Errorf("redirected without client identification: Location=%q", w.Header().Get("Location"))
	}
}

func TestEndSession_UnknownClientID_DoesNotRedirect(t *testing.T) {
	// client_id supplied but not found in the database → no redirect.
	appSvc := &mockAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	h := newTestEndSessionHandler(appSvc, &mockOAuthService{})

	target := "/oauth/logout?client_id=unknown&post_logout_redirect_uri=" +
		url.QueryEscape("https://any.example.com/cb")
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code == http.StatusFound {
		t.Errorf("redirected for unknown client: Location=%q", w.Header().Get("Location"))
	}
}

func TestEndSession_ClientIDExtractedFromIDTokenHint(t *testing.T) {
	// When no explicit client_id is given but id_token_hint has a known
	// audience, the handler must use it to validate the redirect URI.
	registeredURI := "https://app.example.com/logout"
	appSvc := &mockAppService{
		getByClientID: func(_ context.Context, clientID string) (*model.App, error) {
			if clientID != "hinted-client" {
				return nil, fmt.Errorf("not found")
			}
			return &model.App{
				ClientID:     "hinted-client",
				RedirectURIs: model.StringArray{registeredURI},
			}, nil
		},
	}
	h := newTestEndSessionHandler(appSvc, &mockOAuthService{})

	hint := buildJWTPayload(map[string]interface{}{
		"sub": "99",
		"aud": "hinted-client",
	})
	target := "/oauth/logout?id_token_hint=" + url.QueryEscape(hint) +
		"&post_logout_redirect_uri=" + url.QueryEscape(registeredURI)
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect); client_id should have been extracted from hint", w.Code)
	}
}

func TestEndSession_SpoofedIDTokenHint_UnregisteredURI_NoRedirect(t *testing.T) {
	// An attacker crafts an id_token_hint claiming a real client_id but provides
	// an unregistered post_logout_redirect_uri.  The URI validation must still
	// block the redirect.
	appSvc := &mockAppService{
		getByClientID: func(_ context.Context, clientID string) (*model.App, error) {
			if clientID != "real-client" {
				return nil, fmt.Errorf("not found")
			}
			return &model.App{
				ClientID:     "real-client",
				RedirectURIs: model.StringArray{"https://legit.example.com/ok"},
			}, nil
		},
	}
	h := newTestEndSessionHandler(appSvc, &mockOAuthService{})

	// Hint claims real-client but URI is attacker-controlled
	hint := buildJWTPayload(map[string]interface{}{
		"aud": "real-client",
	})
	target := "/oauth/logout?id_token_hint=" + url.QueryEscape(hint) +
		"&post_logout_redirect_uri=" + url.QueryEscape("https://evil.example.com/steal")
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code == http.StatusFound {
		t.Errorf("open redirect not blocked: Location=%q", w.Header().Get("Location"))
	}
}

func TestEndSession_PostForm_RegisteredURI_Redirects(t *testing.T) {
	// Verify that the POST form path is also protected / works correctly.
	registeredURI := "https://app.example.com/logout"
	appSvc := &mockAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) {
			return &model.App{RedirectURIs: model.StringArray{registeredURI}}, nil
		},
	}
	h := newTestEndSessionHandler(appSvc, &mockOAuthService{})

	form := url.Values{}
	form.Set("client_id", "my-app")
	form.Set("post_logout_redirect_uri", registeredURI)
	r := httptest.NewRequest(http.MethodPost, "/oauth/logout",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.EndSession(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 for POST form with registered URI", w.Code)
	}
}
