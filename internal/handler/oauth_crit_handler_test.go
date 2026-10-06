// Package handler — white-box handler-level tests for the four CRIT fixes.
//
// CRIT-01: /oauth/introspect requires client authentication (already present in
//
//	the handler; these tests document and guard that behaviour).
//
// CRIT-03: POST /oauth/authorize rejects requests whose CSRF double-submit
//
//	cookie does not match the form field.
//
// CRIT-04: GET /oauth/authorize for an already-authenticated user renders the
//
//	consent page instead of immediately issuing an authorization code.
//	POST /oauth/authorize with action=consent processes the user's
//	explicit Allow/Deny choice.
package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// CRIT-specific mock types
// ---------------------------------------------------------------------------

// critAppService implements service.AppService with injectable GetByClientID
// and ValidateClientCredentials — the two methods exercised by the CRIT tests.
// All other methods return a harmless zero value.
type critAppService struct {
	getByClientID             func(ctx context.Context, clientID string) (*model.App, error)
	validateClientCredentials func(ctx context.Context, clientID, secret string) (*model.App, error)
}

func (m *critAppService) GetByClientID(ctx context.Context, clientID string) (*model.App, error) {
	if m.getByClientID != nil {
		return m.getByClientID(ctx, clientID)
	}
	return nil, errors.New("not found")
}
func (m *critAppService) ValidateClientCredentials(ctx context.Context, clientID, secret string) (*model.App, error) {
	if m.validateClientCredentials != nil {
		return m.validateClientCredentials(ctx, clientID, secret)
	}
	return nil, errors.New("invalid credentials")
}
func (m *critAppService) List(_ context.Context) ([]model.App, error) { return nil, nil }
func (m *critAppService) GetByID(_ context.Context, _ uint) (*model.App, error) {
	return nil, errors.New("not found")
}
func (m *critAppService) GetByOwnerID(_ context.Context, _ uint) ([]model.App, error) {
	return nil, nil
}
func (m *critAppService) Create(_ context.Context, _ dto.CreateAppRequest, _ uint) (*model.App, string, error) {
	return nil, "", errors.New("not implemented")
}
func (m *critAppService) Update(_ context.Context, _ uint, _ dto.UpdateAppRequest) (*model.App, error) {
	return nil, errors.New("not implemented")
}
func (m *critAppService) Delete(_ context.Context, _ uint) error { return nil }
func (m *critAppService) RotateSecret(_ context.Context, _ uint) (*model.App, string, error) {
	return nil, "", errors.New("not implemented")
}
func (m *critAppService) GetAllAppURLs(_ context.Context) ([]string, error) { return nil, nil }

// Compile-time interface compliance check.
var _ service.AppService = (*critAppService)(nil)

// critOAuthService implements service.OAuthService with injectable Authorize
// and Introspect.  Revoke is a no-op; all other methods panic.
type critOAuthService struct {
	authorize  func(ctx context.Context, req dto.AuthorizeRequest, userID uint) (string, error)
	introspect func(ctx context.Context, token string, requestingClientID string) (*dto.IntrospectResponse, error)
}

func (m *critOAuthService) Authorize(ctx context.Context, req dto.AuthorizeRequest, userID uint) (string, error) {
	if m.authorize != nil {
		return m.authorize(ctx, req, userID)
	}
	panic("Authorize called unexpectedly")
}
func (m *critOAuthService) Token(_ context.Context, _ dto.TokenRequest, _, _ string) (*dto.TokenResponse, error) {
	panic("Token called unexpectedly")
}
func (m *critOAuthService) ExchangeToken(_ context.Context, _ url.Values, _, _ string) (*dto.TokenResponse, error) {
	panic("ExchangeToken called unexpectedly")
}
func (m *critOAuthService) Introspect(ctx context.Context, token string, requestingClientID string) (*dto.IntrospectResponse, error) {
	if m.introspect != nil {
		return m.introspect(ctx, token, requestingClientID)
	}
	return &dto.IntrospectResponse{Active: false}, nil
}
func (m *critOAuthService) Revoke(_ context.Context, _ string, _ uint, _ string) error { return nil }
func (m *critOAuthService) GetUserInfo(_ context.Context, _ uint, _ string) (*dto.UserInfoResponse, error) {
	panic("GetUserInfo called unexpectedly")
}
func (m *critOAuthService) GetOpenIDConfiguration(_ string) *dto.OpenIDConfiguration {
	panic("GetOpenIDConfiguration called unexpectedly")
}
func (m *critOAuthService) GetJWKS() dto.JWKS { panic("GetJWKS called unexpectedly") }
func (m *critOAuthService) ValidatePasswordResetToken(_ context.Context, _ string) (string, bool) {
	panic("ValidatePasswordResetToken called unexpectedly")
}

// Compile-time interface compliance check.
var _ service.OAuthService = (*critOAuthService)(nil)

// critAuthService implements service.AuthService with an injectable Login.
// Logout is a no-op; all other methods panic (they are not exercised here).
type critAuthService struct {
	login func(ctx context.Context, req dto.LoginRequest) (*dto.LoginResponse, error)
}

func (m *critAuthService) Login(ctx context.Context, req dto.LoginRequest) (*dto.LoginResponse, error) {
	if m.login != nil {
		return m.login(ctx, req)
	}
	return nil, service.ErrInvalidCredentials
}
func (m *critAuthService) Signup(_ context.Context, _ dto.SignupRequest) (*model.User, string, error) {
	panic("Signup called unexpectedly")
}
func (m *critAuthService) VerifyEmail(_ context.Context, _ string) error {
	panic("VerifyEmail called unexpectedly")
}
func (m *critAuthService) AdminLogin(_ context.Context, _ dto.AdminLoginRequest) (*dto.LoginResponse, error) {
	panic("AdminLogin called unexpectedly")
}
func (m *critAuthService) RefreshTokens(_ context.Context, _ string) (*dto.RefreshResponse, error) {
	panic("RefreshTokens called unexpectedly")
}
func (m *critAuthService) Logout(_ context.Context, _ uint) error { return nil }
func (m *critAuthService) RequestPasswordReset(_ context.Context, _ string, _ *auth.AppContext) (string, error) {
	panic("RequestPasswordReset called unexpectedly")
}
func (m *critAuthService) ResetPassword(_ context.Context, _, _ string) error {
	panic("ResetPassword called unexpectedly")
}
func (m *critAuthService) ChangePassword(_ context.Context, _ uint, _, _ string) error {
	panic("ChangePassword called unexpectedly")
}
func (m *critAuthService) ValidateInviteToken(_ context.Context, _ string) (*dto.InviteValidationResponse, error) {
	panic("ValidateInviteToken called unexpectedly")
}
func (m *critAuthService) AcceptInvite(_ context.Context, _, _, _ string) (*dto.LoginResponse, error) {
	panic("AcceptInvite called unexpectedly")
}
func (m *critAuthService) WithMFA(_ service.MFAService) service.AuthService { return m }
func (m *critAuthService) AuthenticateAccount(context.Context, string, string, string) (*model.User, error) {
	return nil, errors.New("not used")
}

// Compile-time interface compliance check.
var _ service.AuthService = (*critAuthService)(nil)

// ---------------------------------------------------------------------------
// Test factory helpers
// ---------------------------------------------------------------------------

// critTestSecretKey is a deterministic 32-byte key shared by all CRIT handler
// tests so that consent tokens issued in one step can be validated in the next.
var critTestSecretKey = []byte("crit-test-secret-key-32bytes-pad")

// newCritTestHandler returns an OAuthHandler configured for the CRIT tests.
// It wires in the real TemplateService (templates are embedded in the binary)
// and uses critTestSecretKey for CSRF / consent-token HMAC.
func newCritTestHandler(
	appSvc service.AppService,
	oauthSvc service.OAuthService,
	authSvc service.AuthService,
) *OAuthHandler {
	return &OAuthHandler{
		oauthService:    oauthSvc,
		authService:     authSvc,
		appService:      appSvc,
		templateService: service.NewTemplateService(),
		issuer:          "http://auth.example.com", // HTTP → httpsRequired=false
		secretKey:       critTestSecretKey,
		httpsRequired:   false,
	}
}

// withAuthenticatedUser injects a userID into the request context, simulating
// the authentication middleware for tests that need an authenticated user.
func withAuthenticatedUser(r *http.Request, userID uint) *http.Request {
	ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, userID)
	return r.WithContext(ctx)
}

// attachCSRFCookie adds a _csrf cookie to the request with the given token value.
// The same value must also be present in the form body as csrf_token.
func attachCSRFCookie(r *http.Request, tokenValue string) {
	r.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: tokenValue})
}

// ---------------------------------------------------------------------------
// CRIT-01: /oauth/introspect — client authentication required
// ---------------------------------------------------------------------------

func TestCRIT01_Introspect_NoClientID_Returns401(t *testing.T) {
	// RFC 7662 §2.1: the introspection endpoint MUST require client auth.
	// Omitting client_id entirely must result in a 401 response.
	h := newCritTestHandler(&critAppService{}, &critOAuthService{}, &critAuthService{})

	form := url.Values{"token": {"some-opaque-token"}}
	r := httptest.NewRequest(http.MethodPost, "/oauth/introspect",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Introspect(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (unauthenticated introspect not rejected)", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "invalid_client") {
		t.Errorf("body = %q, want invalid_client error", body)
	}
}

func TestCRIT01_Introspect_InvalidCredentials_Returns401(t *testing.T) {
	// Supplying a client_id with wrong credentials must also be rejected with 401.
	appSvc := &critAppService{
		validateClientCredentials: func(_ context.Context, _, _ string) (*model.App, error) {
			return nil, errors.New("bad credentials")
		},
	}
	h := newCritTestHandler(appSvc, &critOAuthService{}, &critAuthService{})

	form := url.Values{
		"token":         {"some-opaque-token"},
		"client_id":     {"my-client"},
		"client_secret": {"wrong-secret"},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/introspect",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Introspect(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "invalid_client") {
		t.Errorf("body = %q, want invalid_client error", body)
	}
}

func TestCRIT01_Introspect_ValidCredentials_Returns200(t *testing.T) {
	// An authenticated client supplying a valid token must receive a 200 with
	// active:true in the JSON body.
	appSvc := &critAppService{
		validateClientCredentials: func(_ context.Context, clientID, secret string) (*model.App, error) {
			if clientID == "my-client" && secret == "correct-secret" {
				return &model.App{ClientID: clientID}, nil
			}
			return nil, errors.New("invalid")
		},
	}
	oauthSvc := &critOAuthService{
		introspect: func(_ context.Context, _ string, _ string) (*dto.IntrospectResponse, error) {
			return &dto.IntrospectResponse{Active: true}, nil
		},
	}
	h := newCritTestHandler(appSvc, oauthSvc, &critAuthService{})

	form := url.Values{
		"token":         {"some-opaque-token"},
		"client_id":     {"my-client"},
		"client_secret": {"correct-secret"},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/introspect",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Introspect(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"active":true`) {
		t.Errorf("body = %q, want active:true", body)
	}
}

// ---------------------------------------------------------------------------
// CRIT-03: POST /oauth/authorize — CSRF double-submit cookie protection
// ---------------------------------------------------------------------------

func TestCRIT03_AuthorizePost_NoCsrfCookie_RendersError(t *testing.T) {
	// The POST handler must reject requests that have no _csrf cookie.
	// The handler calls auth.ValidateCSRFToken which returns false when no
	// cookie is present, causing renderOAuthError to return a 400 error page.
	h := newCritTestHandler(&critAppService{}, &critOAuthService{}, &critAuthService{})

	form := url.Values{
		"client_id":    {"my-app"},
		"redirect_uri": {"https://app.example.com/cb"},
		// No csrf_token form field and no cookie.
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (CSRF check failed)", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "CSRF") && !strings.Contains(body, "csrf") {
		t.Errorf("error body %q does not mention CSRF", body)
	}
}

func TestCRIT03_AuthorizePost_MismatchedCsrfToken_RendersError(t *testing.T) {
	// If the _csrf cookie and the csrf_token form field contain different values,
	// the handler must reject the request — this is the cross-site forgery scenario.
	h := newCritTestHandler(&critAppService{}, &critOAuthService{}, &critAuthService{})

	form := url.Values{
		"client_id":    {"my-app"},
		"redirect_uri": {"https://app.example.com/cb"},
		"csrf_token":   {"attacker-controlled-value"},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Cookie carries a DIFFERENT value than the form field.
	attachCSRFCookie(r, "server-set-csrf-value")
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (CSRF mismatch not rejected)", w.Code)
	}
}

func TestCRIT03_AuthorizePost_MatchingCsrf_PassesGuard(t *testing.T) {
	// When the cookie and form field carry the same value the CSRF guard must
	// pass.  The handler proceeds to the client lookup stage and fails there
	// (unknown client) — but the failure reason must NOT be a CSRF error.
	h := newCritTestHandler(&critAppService{}, &critOAuthService{}, &critAuthService{})

	const csrfValue = "matching-csrf-abc123"
	form := url.Values{
		"client_id":    {"unknown-client"},
		"redirect_uri": {"https://app.example.com/cb"},
		"csrf_token":   {csrfValue},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attachCSRFCookie(r, csrfValue) // Cookie matches form field.
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	// The CSRF guard must have passed: error is about an invalid client, not CSRF.
	body := w.Body.String()
	if strings.Contains(body, "CSRF") || strings.Contains(body, "csrf") {
		t.Errorf("CSRF error returned despite matching token — guard is broken: %q", body)
	}
	// The handler hit the client-lookup step; it renders a 400 error page
	// saying "Unknown client".
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid_client after CSRF passes)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CRIT-04: Consent screen — unauthenticated + consent flow
// ---------------------------------------------------------------------------

func TestCRIT04_GET_AuthenticatedUser_ShowsConsentPage(t *testing.T) {
	// An already-authenticated user hitting GET /oauth/authorize must see the
	// consent page (200 HTML), not immediately receive an authorization code
	// redirect.
	app := &model.App{
		ClientID:     "my-app",
		Name:         "Test App",
		Active:       true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	appSvc := &critAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil },
	}
	h := newCritTestHandler(appSvc, &critOAuthService{}, &critAuthService{})

	target := "/oauth/authorize?response_type=code&client_id=my-app" +
		"&redirect_uri=" + url.QueryEscape("https://app.example.com/cb") +
		"&scope=openid&state=test-csrf-state"
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r = withAuthenticatedUser(r, 42) // Simulate authenticated middleware.
	w := httptest.NewRecorder()
	h.Authorize(w, r)

	// Must NOT redirect — that would be the pre-CRIT-04 behaviour.
	if w.Code == http.StatusFound {
		t.Errorf("handler issued a redirect (code=%q) for authenticated user — "+
			"consent page not shown (CRIT-04 not fixed)", w.Header().Get("Location"))
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (consent HTML page)", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestCRIT04_GET_UnauthenticatedUser_ShowsLoginPage(t *testing.T) {
	// An unauthenticated user must see the login page, not the consent page.
	app := &model.App{
		ClientID:     "my-app",
		Name:         "Test App",
		Active:       true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	appSvc := &critAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil },
	}
	h := newCritTestHandler(appSvc, &critOAuthService{}, &critAuthService{})

	target := "/oauth/authorize?response_type=code&client_id=my-app" +
		"&redirect_uri=" + url.QueryEscape("https://app.example.com/cb") +
		"&state=test-csrf-state"
	r := httptest.NewRequest(http.MethodGet, target, nil)
	// No user ID in context → unauthenticated.
	w := httptest.NewRecorder()
	h.Authorize(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (login HTML page)", w.Code)
	}
	if w.Code == http.StatusFound {
		t.Error("unauthenticated request should not be redirected")
	}
}

// metaRefreshURL extracts the target URL from a meta-refresh HTML page
// rendered by renderRedirectPage.  Returns "" if no meta-refresh is found.
func metaRefreshURL(body string) string {
	// Look for content="0;url=..." in the body.
	const needle = `content="0;url=`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	// Unescape HTML entities that HTMLEscapeString may have introduced
	// (& → &, " → ").
	raw := rest[:end]
	raw = strings.ReplaceAll(raw, "&amp;", "&")
	raw = strings.ReplaceAll(raw, "&#34;", `"`)
	raw = strings.ReplaceAll(raw, "&lt;", "<")
	raw = strings.ReplaceAll(raw, "&gt;", ">")
	return raw
}

func TestCRIT04_POST_ConsentAllow_RedirectsWithCode(t *testing.T) {
	// When the user explicitly clicks "Allow" (authorized=true) with a valid
	// consent token, the handler must return a 200 meta-refresh page that
	// navigates to the client with an authorization code.
	// (The handler uses renderRedirectPage instead of http.Redirect to avoid
	// CSP form-action violations in browsers that follow the CSP Level-2 spec.)
	app := &model.App{
		ClientID:     "my-app",
		Name:         "Test App",
		Active:       true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	appSvc := &critAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil },
	}
	oauthSvc := &critOAuthService{
		authorize: func(_ context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
			return "test-authorization-code", nil
		},
	}
	h := newCritTestHandler(appSvc, oauthSvc, &critAuthService{})

	// Issue a valid consent token for userID=42, clientID="my-app".
	consentToken, err := auth.IssueConsentToken(42, "my-app", critTestSecretKey)
	if err != nil {
		t.Fatalf("IssueConsentToken: %v", err)
	}

	const csrfValue = "csrf-for-consent-allow-test"
	form := url.Values{
		"action":        {"consent"},
		"authorized":    {"true"},
		"client_id":     {"my-app"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"response_type": {"code"},
		"csrf_token":    {csrfValue},
		"consent_token": {consentToken},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attachCSRFCookie(r, csrfValue)
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	// Handler now returns 200 OK with a meta-refresh page instead of 302.
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (meta-refresh redirect page with code)", w.Code)
	}
	// Must NOT issue a bare 302 redirect (that would cause form-action CSP issues).
	if w.Code == http.StatusFound {
		t.Errorf("handler issued HTTP 302 redirect — renderRedirectPage should have been used instead")
	}
	// Extract the target URL from the meta-refresh page.
	loc := metaRefreshURL(w.Body.String())
	if loc == "" {
		t.Fatalf("response body has no meta-refresh URL; body = %q", w.Body.String())
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("meta-refresh URL %q is not a valid URL: %v", loc, err)
	}
	if got := parsed.Query().Get("code"); got == "" {
		t.Errorf("redirect URL %q is missing the 'code' parameter", loc)
	}
	if got := parsed.Query().Get("code"); got != "test-authorization-code" {
		t.Errorf("code = %q, want test-authorization-code", got)
	}
}

func TestCRIT04_POST_ConsentDeny_RedirectsWithAccessDenied(t *testing.T) {
	// When the user clicks "Deny" (authorized=false) the handler must return a
	// 200 meta-refresh page navigating to the client with error=access_denied,
	// and must NOT issue an authorization code.
	app := &model.App{
		ClientID:     "my-app",
		Name:         "Test App",
		Active:       true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	appSvc := &critAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil },
	}
	h := newCritTestHandler(appSvc, &critOAuthService{}, &critAuthService{})

	consentToken, _ := auth.IssueConsentToken(42, "my-app", critTestSecretKey)

	const csrfValue = "csrf-for-consent-deny-test"
	form := url.Values{
		"action":        {"consent"},
		"authorized":    {"false"}, // User denies.
		"client_id":     {"my-app"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"response_type": {"code"},
		"csrf_token":    {csrfValue},
		"consent_token": {consentToken},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attachCSRFCookie(r, csrfValue)
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	// Handler now returns 200 OK with a meta-refresh page instead of 302.
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (meta-refresh redirect page)", w.Code)
	}
	if w.Code == http.StatusFound {
		t.Errorf("handler issued HTTP 302 redirect — renderRedirectPage should have been used instead")
	}
	// Extract the target URL from the meta-refresh page.
	loc := metaRefreshURL(w.Body.String())
	if loc == "" {
		t.Fatalf("response body has no meta-refresh URL; body = %q", w.Body.String())
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("meta-refresh URL %q is not a valid URL: %v", loc, err)
	}
	if got := parsed.Query().Get("error"); got != "access_denied" {
		t.Errorf("redirect error = %q, want access_denied", got)
	}
	if code := parsed.Query().Get("code"); code != "" {
		t.Errorf("redirect should not contain 'code' on denial, got %q", code)
	}
}

func TestCRIT04_POST_InvalidConsentToken_RendersError(t *testing.T) {
	// A tampered or expired consent token must be rejected.  The handler must
	// render an error page, not redirect with a code.
	app := &model.App{
		ClientID:     "my-app",
		Name:         "Test App",
		Active:       true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	appSvc := &critAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil },
	}
	h := newCritTestHandler(appSvc, &critOAuthService{}, &critAuthService{})

	const csrfValue = "csrf-for-bad-consent-test"
	form := url.Values{
		"action":        {"consent"},
		"authorized":    {"true"},
		"client_id":     {"my-app"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"response_type": {"code"},
		"csrf_token":    {csrfValue},
		"consent_token": {"tampered.bad.token"}, // Invalid — signature will not verify.
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attachCSRFCookie(r, csrfValue)
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	// Must not issue a code redirect.
	if w.Code == http.StatusFound {
		t.Errorf("handler issued redirect despite invalid consent token: %q",
			w.Header().Get("Location"))
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (error page for invalid consent token)", w.Code)
	}
}

func TestCRIT04_POST_ClientIDMismatchInConsentToken_RendersError(t *testing.T) {
	// If the consent_token was issued for a DIFFERENT client than the one
	// submitted in the form, the handler must reject the request.
	// This prevents a user from swapping the client_id after seeing the
	// consent page.
	app := &model.App{
		ClientID:     "my-app",
		Name:         "Test App",
		Active:       true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	appSvc := &critAppService{
		getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil },
	}
	h := newCritTestHandler(appSvc, &critOAuthService{}, &critAuthService{})

	// Consent token was issued for "other-client", but form says "my-app".
	consentToken, _ := auth.IssueConsentToken(42, "other-client", critTestSecretKey)

	const csrfValue = "csrf-for-mismatch-test"
	form := url.Values{
		"action":        {"consent"},
		"authorized":    {"true"},
		"client_id":     {"my-app"}, // Mismatch!
		"redirect_uri":  {"https://app.example.com/cb"},
		"response_type": {"code"},
		"csrf_token":    {csrfValue},
		"consent_token": {consentToken},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attachCSRFCookie(r, csrfValue)
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	if w.Code == http.StatusFound {
		t.Errorf("handler accepted mismatched consent token and issued redirect: %q",
			w.Header().Get("Location"))
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (client mismatch in consent token)", w.Code)
	}
}
