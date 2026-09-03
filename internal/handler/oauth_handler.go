package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/service"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/tokenexchange"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

type OAuthHandler struct {
	oauthService    service.OAuthService
	authService     service.AuthService
	appService      service.AppService
	templateService *service.TemplateService
	tokenService    *auth.TokenService
	issuer          string
	// secretKey is used for CSRF-token signing and consent-token HMAC
	// (CRIT-03 / CRIT-04).  A random key is generated at startup when
	// the caller passes nil so that development environments with no
	// configured SecretKeyBase still get working CSRF protection within
	// a single process lifetime.
	secretKey     []byte
	httpsRequired bool // sets Secure flag on CSRF cookies
	// dpopAlgs lists the DPoP proof signing algorithms to advertise in OIDC
	// discovery (dpop_signing_alg_values_supported, RFC 9449 §5.1). Empty when
	// DPoP is disabled (DPOP_MODE=off), so discovery omits the parameter.
	dpopAlgs []string
	// jwksCacheMaxAge is the Cache-Control max-age (seconds) advertised on the
	// JWKS endpoint. <= 0 disables caching (no-store). RFC-002.
	jwksCacheMaxAge int
	// extraGrantTypes are additional grant types advertised in OIDC discovery
	// beyond the always-supported set (e.g. the RFC 8693 token-exchange URN when
	// TOKEN_EXCHANGE_MODE=enforce). Empty when none are enabled.
	extraGrantTypes []string
	// refreshCookie configures the first-party admin-console refresh-token
	// cookie channel. Disabled (zero value) unless SetRefreshCookie is called
	// with a non-empty client id. Tier-0 admin session hardening.
	refreshCookie refreshCookieConfig

	// autoDefense receives failed/successful hosted-login attempts (P3-5).
	autoDefense loginDefense
}

// refreshCookieConfig delivers a first-party public client's refresh token as
// an HttpOnly; Secure; SameSite=Strict cookie so a browser SPA can refresh
// silently without the refresh token ever being readable by JavaScript.
type refreshCookieConfig struct {
	clientID string // first-party admin-console client_id; empty disables the channel
	name     string // cookie name (refreshCookieName)
	path     string // cookie path (refreshCookiePath) — scopes it to the token endpoint
	secure   bool   // Secure flag; true in production
	maxAge   int    // cookie Max-Age in seconds (refresh-token TTL)
}

const (
	refreshCookieName = "refresh_token"
	refreshCookiePath = "/oauth/token"
)

// enabled reports whether the cookie channel is configured.
func (c refreshCookieConfig) enabled() bool { return c.clientID != "" }

// handles reports whether refresh tokens for clientID are cookie-borne.
func (c refreshCookieConfig) handles(clientID string) bool {
	return c.enabled() && clientID == c.clientID
}

// loginDefense is the subset of *service.AutoDefenseService the hosted login
// path needs. Kept as an interface so tests can observe the calls.
type loginDefense interface {
	RecordFailedLogin(ctx context.Context, ip, userAgent string)
	RecordSuccessfulLogin(ip string)
}

// SetAutoDefenseService wires the hosted login form (POST /oauth/authorize,
// password path) into IP-based auto-defense, so browser-path password
// spraying is tracked the same way as POST /api/auth/login (P3-5). A nil
// service leaves the channel disabled.
func (h *OAuthHandler) SetAutoDefenseService(autoDefense *service.AutoDefenseService) {
	if autoDefense == nil {
		h.autoDefense = nil
		return
	}
	h.autoDefense = autoDefense
}

// SetRefreshCookie enables the first-party admin-console refresh-token cookie
// channel for the given client id. A zero/empty clientID leaves it disabled.
// refreshTTL sets the cookie Max-Age; secure sets the Secure flag (true in
// production). Tier-0 admin session hardening.
func (h *OAuthHandler) SetRefreshCookie(clientID string, refreshTTL time.Duration, secure bool) {
	h.refreshCookie = refreshCookieConfig{
		clientID: clientID,
		name:     refreshCookieName,
		path:     refreshCookiePath,
		secure:   secure,
		maxAge:   int(refreshTTL.Seconds()),
	}
}

// writeRefreshCookie stores the refresh token in an HttpOnly cookie so it is
// never exposed to JavaScript (XSS-safe). SameSite=Strict and a token-endpoint
// path minimise where the browser will send it.
func (h *OAuthHandler) writeRefreshCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.refreshCookie.name,
		Value:    value,
		Path:     h.refreshCookie.path,
		MaxAge:   h.refreshCookie.maxAge,
		HttpOnly: true,
		Secure:   h.refreshCookie.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// SetJWKSCacheMaxAge configures the Cache-Control max-age (in seconds) for the
// JWKS endpoint. A value <= 0 disables caching.
func (h *OAuthHandler) SetJWKSCacheMaxAge(seconds int) {
	h.jwksCacheMaxAge = seconds
}

// SetExtraGrantTypes configures additional grant types to advertise in OIDC
// discovery (appended to grant_types_supported).
func (h *OAuthHandler) SetExtraGrantTypes(grantTypes []string) {
	h.extraGrantTypes = grantTypes
}

// SetDPoPSigningAlgs configures the DPoP proof signing algorithms advertised in
// the OIDC discovery document. Pass nil/empty to advertise no DPoP support.
func (h *OAuthHandler) SetDPoPSigningAlgs(algs []string) {
	h.dpopAlgs = algs
}

func NewOAuthHandler(
	oauthService service.OAuthService,
	authService service.AuthService,
	appService service.AppService,
	templateService *service.TemplateService,
	tokenService *auth.TokenService,
	issuer string,
	secretKey []byte,
) *OAuthHandler {
	if len(secretKey) == 0 {
		// Development/test fallback: random key per process startup.
		// Consent tokens will not survive restarts, which is acceptable
		// in non-production environments.
		k := make([]byte, 32)
		// crypto/rand.Read does not fail on Linux; this is a dev-only fallback
		// key used when no SECRET_KEY_BASE is configured.
		_, _ = rand.Read(k)
		secretKey = k
	}
	return &OAuthHandler{
		oauthService:    oauthService,
		authService:     authService,
		appService:      appService,
		templateService: templateService,
		tokenService:    tokenService,
		issuer:          issuer,
		secretKey:       secretKey,
		httpsRequired:   strings.HasPrefix(issuer, "https://"),
	}
}

// GET /oauth/authorize
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Parse OAuth parameters
	maxAge := -1 // -1 = not specified
	if rawMaxAge := r.URL.Query().Get("max_age"); rawMaxAge != "" {
		if v, err := strconv.Atoi(rawMaxAge); err == nil && v >= 0 {
			maxAge = v
		}
	}
	req := dto.AuthorizeRequest{
		ResponseType:        r.URL.Query().Get("response_type"),
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		MaxAge:              maxAge,
	}

	// Validate required parameters
	if req.ClientID == "" {
		h.renderOAuthError(w, "invalid_request", "client_id is required", "")
		return
	}

	// Get app details for display
	app, err := h.appService.GetByClientID(r.Context(), req.ClientID)
	if err != nil {
		h.renderOAuthError(w, "invalid_client", "Unknown client", "")
		return
	}

	// Validate redirect URI - check for dangerous schemes and ensure it's registered
	if req.RedirectURI == "" {
		h.renderOAuthError(w, "invalid_request", "redirect_uri is required", "")
		return
	}
	// NEW-02 fix: pass h.httpsRequired so that HTTP redirect URIs are rejected
	// when the authorization server runs behind HTTPS (RFC 6749 §10.6).
	// h.httpsRequired is true when the configured issuer starts with "https://".
	if err := auth.ValidateRedirectURI(req.RedirectURI, app.RedirectURIs, h.httpsRequired); err != nil {
		// HIGH-01 fix: log the full error internally; never forward raw Go error
		// strings to the client.  redirectURIErrorDescription maps each sentinel
		// error to a safe, static description.
		logger.Warnf("HIGH-01: redirect_uri validation failed (client_id=%s redirect_uri=%s): %v",
			req.ClientID, req.RedirectURI, err)
		h.renderOAuthError(w, "invalid_request", redirectURIErrorDescription(err), "")
		return
	}

	// HIGH-06 fix: require the state parameter (RFC 6749 §10.12).
	// The state parameter is the primary CSRF defence for OAuth clients.
	// Requiring it server-side prevents clients from accidentally implementing
	// a stateless, CSRF-vulnerable authorization flow.
	if req.State == "" {
		h.renderOAuthError(w, "invalid_request", "state parameter is required", "")
		return
	}

	// CRIT-03: generate a CSRF token and set it as a SameSite=Strict cookie.
	// The same value is embedded in the form so we can verify it on POST.
	csrfToken, err := auth.GenerateCSRFToken(w, h.httpsRequired)
	if err != nil {
		h.renderOAuthError(w, "server_error", "failed to generate CSRF token", "")
		return
	}

	// Check if user is authenticated
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		// User not authenticated — render login page with CSRF token.
		_ = h.templateService.RenderLogin(w, service.LoginPageData{
			AppName:             app.Name,
			ClientID:            req.ClientID,
			RedirectURI:         req.RedirectURI,
			ResponseType:        req.ResponseType,
			Scope:               req.Scope,
			State:               req.State,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			Nonce:               req.Nonce,
			CSRFToken:           csrfToken,
			MaxAge:              req.MaxAge,
		})
		return
	}

	// CRIT-04: user is already authenticated — show consent page instead of
	// issuing a code immediately.  The user must explicitly click "Allow".
	if req.ResponseType == "" {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "invalid_request", "response_type is required")
		return
	}

	h.renderConsentPage(w, req, app.Name, userID, csrfToken)
}

// POST /oauth/authorize — handles two actions:
//
//	action=login   (default) — authenticates email+password credentials and,
//	                           on success, renders the consent page.
//	action=consent           — validates a signed consent token and the user's
//	                           explicit "Allow" / "Deny" choice, then issues
//	                           the authorization code or redirects with an error.
//
// CRIT-03: both actions first validate the CSRF double-submit cookie.
// CRIT-04: on successful login the handler renders the consent page rather
//
//	than immediately issuing an authorization code.
func (h *OAuthHandler) AuthorizePost(w http.ResponseWriter, r *http.Request) {
	// G120: cap the form body to 1 MB to prevent memory-exhaustion via huge POST bodies.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.renderOAuthError(w, "invalid_request", "Failed to parse form", "")
		return
	}

	// CRIT-03: validate CSRF before processing any credentials or consent.
	if !auth.ValidateCSRFToken(r, r.FormValue("csrf_token")) {
		h.renderOAuthError(w, "invalid_request", "Invalid or missing CSRF token", "")
		return
	}

	// Extract OAuth parameters from form.
	// MaxAge uses -1 as a sentinel meaning "not specified by the client".
	// The zero value of int (0) would mean "re-authenticate within 0 seconds",
	// which is always impossible and would cause ErrReauthRequired for every
	// consent submission.  We preserve max_age from the hidden form field when
	// the login page included it, otherwise default to -1 (skip the check).
	maxAge := -1
	if raw := r.FormValue("max_age"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			maxAge = v
		}
	}
	req := dto.AuthorizeRequest{
		ResponseType:        r.FormValue("response_type"),
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		MaxAge:              maxAge,
	}

	// Get app details — required for both login and consent paths.
	app, err := h.appService.GetByClientID(r.Context(), req.ClientID)
	if err != nil {
		h.renderOAuthError(w, "invalid_client", "Unknown client", "")
		return
	}

	// Validate redirect URI early so we can use redirectWithError safely.
	if req.RedirectURI == "" {
		h.renderOAuthError(w, "invalid_request", "redirect_uri is required", "")
		return
	}
	// NEW-02 fix: same as GET path — pass h.httpsRequired (not false).
	if err := auth.ValidateRedirectURI(req.RedirectURI, app.RedirectURIs, h.httpsRequired); err != nil {
		// HIGH-01 fix: log full detail internally; send only a controlled description.
		logger.Warnf("HIGH-01: redirect_uri validation failed (client_id=%s redirect_uri=%s): %v",
			req.ClientID, req.RedirectURI, err)
		h.renderOAuthError(w, "invalid_request", redirectURIErrorDescription(err), "")
		return
	}

	action := r.FormValue("action")

	// -----------------------------------------------------------------------
	// Path A: consent — user explicitly approved or denied the request.
	// -----------------------------------------------------------------------
	if action == "consent" {
		h.handleConsentPost(w, r, req, app.Name)
		return
	}

	// -----------------------------------------------------------------------
	// Path B: login — validate email + password credentials.
	// -----------------------------------------------------------------------
	email := r.FormValue("email")
	password := r.FormValue("password")

	// renderLoginError re-renders the login page with a fresh CSRF token.
	renderLoginError := func(errorMsg string) {
		csrfToken, _ := auth.GenerateCSRFToken(w, h.httpsRequired)
		_ = h.templateService.RenderLogin(w, service.LoginPageData{
			AppName:             app.Name,
			ClientID:            req.ClientID,
			RedirectURI:         req.RedirectURI,
			ResponseType:        req.ResponseType,
			Scope:               req.Scope,
			State:               req.State,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			Nonce:               req.Nonce,
			Email:               email,
			Error:               errorMsg,
			CSRFToken:           csrfToken,
			MaxAge:              req.MaxAge,
		})
	}

	if email == "" || password == "" {
		renderLoginError("Email and password are required")
		return
	}

	// P3-5: the hosted form is a login endpoint like POST /api/auth/login and
	// must feed the same IP-based auto-defense, otherwise password spraying
	// through the browser path is throttled only by per-account lockout.
	clientIP := middleware.GetClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	loginResp, err := h.authService.Login(r.Context(), dto.LoginRequest{
		Email:       email,
		Password:    password,
		AppClientID: req.ClientID,
	})
	if err != nil {
		if h.autoDefense != nil {
			h.autoDefense.RecordFailedLogin(r.Context(), clientIP, userAgent)
		}
		// errors.Is, not equality: Login returns several *wrapped* errors
		// (ErrRoleNotFound / ErrAccountLocked / ErrUserNotVerified / ErrAppNotFound),
		// which an equality switch would miss — collapsing them all to the
		// generic message and hiding the real reason.
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			renderLoginError("Invalid email or password")
		case errors.Is(err, service.ErrUserNotVerified):
			renderLoginError("Please verify your email address first")
		case errors.Is(err, service.ErrAccountLocked):
			renderLoginError("Your account has been locked. Please try again later")
		case errors.Is(err, service.ErrRoleNotFound):
			renderLoginError("You do not have access to this application")
		case errors.Is(err, service.ErrMFARequired), errors.Is(err, service.ErrMFAInvalidCode):
			renderLoginError("Multi-factor authentication is required to sign in here")
		default:
			renderLoginError("Login failed. Please try again")
		}
		return
	}

	if h.autoDefense != nil {
		h.autoDefense.RecordSuccessfulLogin(clientIP)
	}

	// CRIT-04: login succeeded — show consent page instead of issuing code.
	// Generate a fresh CSRF token for the consent form.
	csrfToken, err := auth.GenerateCSRFToken(w, h.httpsRequired)
	if err != nil {
		renderLoginError("Internal error. Please try again")
		return
	}

	h.renderConsentPage(w, req, app.Name, loginResp.UserID, csrfToken)
}

// handleConsentPost processes the explicit "Allow" / "Deny" consent POST.
// The consent_token field carries a signed user identity that was issued when
// the consent page was rendered (after login or on GET /oauth/authorize for
// an already-authenticated user).
func (h *OAuthHandler) handleConsentPost(w http.ResponseWriter, r *http.Request, req dto.AuthorizeRequest, appName string) {
	// Validate and extract the signed user identity.
	consentTokenStr := r.FormValue("consent_token")
	userID, tokenClientID, err := auth.ValidateConsentToken(consentTokenStr, h.secretKey)
	if err != nil {
		h.renderOAuthError(w, "invalid_request", "Consent session expired or invalid. Please sign in again.", "")
		return
	}

	// Verify the clientID in the consent token matches the form's clientID
	// to prevent a user from swapping the client during consent submission.
	if tokenClientID != req.ClientID {
		h.renderOAuthError(w, "invalid_request", "Client mismatch in consent token", "")
		return
	}

	// Honour the user's explicit choice.
	// NOTE: all outgoing redirects from this handler use renderRedirectPage /
	// redirectWithErrorPage (meta-refresh) instead of http.Redirect (HTTP 302).
	// Firefox applies form-action CSP to the entire redirect chain that follows
	// a form submission; a meta-refresh breaks that chain so the browser treats
	// the navigation to the client's redirect_uri as a normal page load.
	if r.FormValue("authorized") != "true" {
		h.redirectWithErrorPage(w, req.RedirectURI, req.State, "access_denied", "user denied access")
		return
	}

	if req.ResponseType == "" {
		h.redirectWithErrorPage(w, req.RedirectURI, req.State, "invalid_request", "response_type is required")
		return
	}

	code, err := h.oauthService.Authorize(r.Context(), req, userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRoleNotFound):
			h.redirectWithErrorPage(w, req.RedirectURI, req.State, "access_denied", "user does not have access to this application")
		case errors.Is(err, service.ErrReauthRequired):
			h.redirectWithErrorPage(w, req.RedirectURI, req.State, "login_required", "re-authentication required")
		case errors.Is(err, service.ErrPKCERequired):
			h.redirectWithErrorPage(w, req.RedirectURI, req.State, "invalid_request", "this client requires PKCE")
		case errors.Is(err, service.ErrPKCEMethodUnsupported):
			// P3-4: only S256 is supported; "plain" and an omitted method are rejected.
			h.redirectWithErrorPage(w, req.RedirectURI, req.State, "invalid_request", "code_challenge_method must be S256")
		case errors.Is(err, service.ErrInvalidScope):
			// Unknown scope, or one outside the client's allowed_scopes policy (A1).
			h.redirectWithErrorPage(w, req.RedirectURI, req.State, "invalid_scope", "requested scope is not allowed for this client")
		case errors.Is(err, service.ErrAccountLocked):
			// P3-3: a locked account cannot authorize new clients.
			h.redirectWithErrorPage(w, req.RedirectURI, req.State, "access_denied", "account is locked")
		case errors.Is(err, service.ErrAppInactive):
			// P3-3: a deactivated client cannot obtain authorization codes.
			h.redirectWithErrorPage(w, req.RedirectURI, req.State, "unauthorized_client", "client is deactivated")
		default:
			h.redirectWithErrorPage(w, req.RedirectURI, req.State, "server_error", "authorization failed")
		}
		return
	}

	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		h.redirectWithErrorPage(w, req.RedirectURI, req.State, "server_error", "failed to parse redirect URI")
		return
	}

	renderRedirectPage(w, buildAuthzRedirect(redirectURL, code, req.State, h.issuer))
}

// buildAuthzRedirect builds the authorization-response redirect URL, appending
// the authorization code, the optional state, and the issuer identifier (`iss`,
// RFC 9207). The `iss` parameter lets the client confirm which authorization
// server issued the code, defending against IdP mix-up attacks. Existing query
// parameters on the redirect URI are preserved.
func buildAuthzRedirect(redirectURL *url.URL, code, state, issuer string) string {
	query := redirectURL.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	if issuer != "" {
		query.Set("iss", issuer)
	}
	redirectURL.RawQuery = query.Encode()
	return redirectURL.String()
}

// renderConsentPage issues a consent token for userID/clientID, then renders
// the consent HTML page.  Called from both the GET and POST (after login)
// handlers.
func (h *OAuthHandler) renderConsentPage(w http.ResponseWriter, req dto.AuthorizeRequest, appName string, userID uint, csrfToken string) {
	consentToken, err := auth.IssueConsentToken(userID, req.ClientID, h.secretKey)
	if err != nil {
		h.renderOAuthError(w, "server_error", "failed to generate consent token", "")
		return
	}

	_ = h.templateService.RenderConsent(w, service.ConsentPageData{
		AppName:             appName,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		CSRFToken:           csrfToken,
		ConsentToken:        consentToken,
		MaxAge:              req.MaxAge,
	})
}

// renderOAuthError renders the error page
func (h *OAuthHandler) renderOAuthError(w http.ResponseWriter, errorCode, message, returnURL string) {
	_ = h.templateService.RenderError(w, service.ErrorPageData{
		Title:     "Authorization Error",
		Message:   message,
		ErrorCode: errorCode,
		ReturnURL: returnURL,
	})
}

// redirectURIErrorDescription maps a redirect-URI sentinel error to a safe,
// RFC 6749-compliant description that can be sent to clients.  All of the
// auth.ErrRedirectURI* values are static strings with no internal detail, so
// we preserve them verbatim.  Any future error type that we don't recognise
// falls back to a generic phrase, closing the HIGH-01 leak surface entirely.
func redirectURIErrorDescription(err error) string {
	switch {
	case errors.Is(err, auth.ErrRedirectURINotRegistered):
		return "redirect_uri is not registered for this client"
	case errors.Is(err, auth.ErrRedirectURIDangerousScheme):
		return "redirect_uri uses a disallowed scheme"
	case errors.Is(err, auth.ErrRedirectURIHasFragment):
		return "redirect_uri must not contain a fragment"
	case errors.Is(err, auth.ErrRedirectURINotHTTPS):
		return "redirect_uri must use HTTPS"
	case errors.Is(err, auth.ErrRedirectURIPathTraversal):
		return "redirect_uri contains an invalid path"
	case errors.Is(err, auth.ErrRedirectURIInvalidURL):
		return "redirect_uri is not a valid URL"
	default:
		return "invalid redirect_uri"
	}
}

// renderRedirectPage writes a minimal HTML page that navigates the browser to
// targetURL via a <meta http-equiv="refresh"> directive.
//
// This is used instead of http.Redirect when responding to HTML form POSTs so
// that browsers enforcing the CSP Level-2 interpretation of form-action (e.g.
// Firefox) cannot block the redirect to the OAuth client's redirect_uri.
// Under CSP Level 2, form-action is applied to the entire navigation chain
// that follows a form submission — including server-issued 302 redirects.
// A meta-refresh is a page-level navigation and is therefore not subject to
// the form-action restriction, allowing registered cross-origin redirect URIs
// to work correctly without weakening the CSP policy.
func renderRedirectPage(w http.ResponseWriter, targetURL string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	escaped := htmltemplate.HTMLEscapeString(targetURL)
	//nolint:errcheck // G104: write errors on a closing response are not actionable
	fmt.Fprintf(w,
		`<!DOCTYPE html><html><head>`+
			`<meta http-equiv="refresh" content="0;url=%s">`+
			`<title>Redirecting&#8230;</title>`+
			`</head><body></body></html>`,
		escaped,
	)
}

// redirectWithErrorPage builds an OAuth error redirect URL and delivers it via
// renderRedirectPage.  Use this (instead of redirectWithError) when responding
// to form POSTs to avoid the CSP form-action redirect-chain issue.
func (h *OAuthHandler) redirectWithErrorPage(w http.ResponseWriter, redirectURI, state, errorCode, description string) {
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.renderOAuthError(w, errorCode, description, "")
		return
	}
	query := redirectURL.Query()
	query.Set("error", errorCode)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()
	renderRedirectPage(w, redirectURL.String())
}

// redirectWithError redirects to the client with an error
func (h *OAuthHandler) redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode, description string) {
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.renderOAuthError(w, errorCode, description, "")
		return
	}

	query := redirectURL.Query()
	query.Set("error", errorCode)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// POST /oauth/token
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	// G120: cap the request body to 1 MB before any form or JSON decode.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Set no-cache headers
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")

	var req dto.TokenRequest
	contentType := r.Header.Get("Content-Type")

	// Support both JSON and form-urlencoded formats
	if strings.Contains(contentType, "application/json") {
		// Parse JSON body
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, "invalid_request", "failed to parse JSON body", http.StatusBadRequest)
			return
		}
	} else {
		// Parse form data (standard OAuth2)
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, "invalid_request", "failed to parse form", http.StatusBadRequest)
			return
		}
		req = dto.TokenRequest{
			GrantType:    r.FormValue("grant_type"),
			Code:         r.FormValue("code"),
			RedirectURI:  r.FormValue("redirect_uri"),
			ClientID:     r.FormValue("client_id"),
			ClientSecret: r.FormValue("client_secret"),
			RefreshToken: r.FormValue("refresh_token"),
			CodeVerifier: r.FormValue("code_verifier"),
			Scope:        r.FormValue("scope"),
		}
	}

	// Extract client credentials (from header or body)
	clientID, clientSecret := extractClientCredentials(r)
	// Override with body values if provided
	if req.ClientID != "" {
		clientID = req.ClientID
	}
	if req.ClientSecret != "" {
		clientSecret = req.ClientSecret
	}

	if req.GrantType == "" {
		writeOAuthError(w, "invalid_request", "grant_type is required", http.StatusBadRequest)
		return
	}

	// Tier-0 admin session hardening: when the admin console refreshes, its
	// refresh token lives in an HttpOnly cookie (never sent in the body). Read
	// it from the cookie when no explicit refresh_token was supplied so the
	// existing hardened refresh grant (rotation/replay/DPoP) runs unchanged.
	if req.GrantType == "refresh_token" && req.RefreshToken == "" && h.refreshCookie.enabled() {
		if ck, cErr := r.Cookie(h.refreshCookie.name); cErr == nil && ck.Value != "" {
			req.RefreshToken = ck.Value
		}
	}

	// RFC 8693 token exchange is dispatched separately: its parameters are not
	// part of the standard TokenRequest. ExchangeToken is gated by
	// TOKEN_EXCHANGE_MODE and (off/shadow) reports the grant as unsupported.
	if req.GrantType == tokenexchange.GrantType {
		_ = r.ParseForm()
		resp, err := h.oauthService.ExchangeToken(r.Context(), r.Form, clientID, clientSecret)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrInvalidGrantType):
				writeOAuthError(w, "unsupported_grant_type", "unsupported grant type", http.StatusBadRequest)
			case errors.Is(err, service.ErrInvalidCredentials):
				writeOAuthError(w, "invalid_client", "client authentication failed", http.StatusUnauthorized)
			case errors.Is(err, service.ErrInvalidToken):
				writeOAuthError(w, "invalid_grant", "the subject or actor token is invalid", http.StatusBadRequest)
			case errors.Is(err, service.ErrScopeNotSubset):
				writeOAuthError(w, "invalid_scope", "requested scope exceeds the subject's scope", http.StatusBadRequest)
			case errors.Is(err, service.ErrAudienceRequired):
				writeOAuthError(w, "invalid_target", "a target audience or resource is required", http.StatusBadRequest)
			case errors.Is(err, service.ErrExchangeNotAllowed), errors.Is(err, service.ErrImpersonationNotAllowed):
				writeOAuthError(w, "unauthorized_client", "token exchange is not permitted for this client", http.StatusForbidden)
			case errors.Is(err, service.ErrStepUpRequired):
				writeOAuthError(w, "invalid_grant", "impersonation requires a more recent subject authentication", http.StatusBadRequest)
			case errors.Is(err, service.ErrDelegationStepUpRequired):
				writeOAuthError(w, "invalid_grant", "delegation requires the actor to have authenticated with MFA", http.StatusBadRequest)
			case errors.Is(err, service.ErrInvalidExchangeRequest):
				writeOAuthError(w, "invalid_request", "invalid token-exchange request", http.StatusBadRequest)
			default:
				writeOAuthError(w, "server_error", "an internal error occurred", http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, resp)
		return
	}

	response, err := h.oauthService.Token(r.Context(), req, clientID, clientSecret)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidGrantType):
			writeOAuthError(w, "unsupported_grant_type", "unsupported grant type", http.StatusBadRequest)
		case errors.Is(err, service.ErrTokenVetoed):
			// A6: an operator hook refused this grant.
			writeOAuthError(w, "access_denied", "token issuance refused by policy", http.StatusForbidden)
		case errors.Is(err, service.ErrInvalidCode):
			writeOAuthError(w, "invalid_grant", "invalid authorization code", http.StatusBadRequest)
		case errors.Is(err, service.ErrCodeExpired):
			writeOAuthError(w, "invalid_grant", "authorization code expired", http.StatusBadRequest)
		case errors.Is(err, service.ErrInvalidCredentials):
			writeOAuthError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		case errors.Is(err, service.ErrPKCEVerificationFail):
			writeOAuthError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		case errors.Is(err, service.ErrInvalidToken):
			writeOAuthError(w, "invalid_grant", "invalid or expired refresh token", http.StatusBadRequest)
		case errors.Is(err, service.ErrAccountLocked):
			// P3-3: a locked account's refresh token is no longer honoured.
			writeOAuthError(w, "invalid_grant", "account is locked", http.StatusBadRequest)
		case errors.Is(err, service.ErrAppInactive):
			// P3-3: a deactivated client gets no tokens from any grant.
			writeOAuthError(w, "unauthorized_client", "client is deactivated", http.StatusBadRequest)
		case errors.Is(err, service.ErrInvalidScope):
			// P2-5: client_credentials now validates scope like the other grants.
			writeOAuthError(w, "invalid_scope", "unknown or unsupported scope", http.StatusBadRequest)
		case errors.Is(err, service.ErrDPoPRequired):
			writeOAuthError(w, "invalid_dpop_proof", "this client requires a DPoP proof", http.StatusBadRequest)
		case errors.Is(err, service.ErrDPoPKeyMismatch):
			writeOAuthError(w, "invalid_dpop_proof", "DPoP proof does not match the refresh token binding", http.StatusBadRequest)
		default:
			// HIGH-01 fix: never leak raw Go error strings to clients.
			writeOAuthError(w, "server_error", "an internal error occurred", http.StatusInternalServerError)
		}
		return
	}

	// Tier-0 admin session hardening: for the first-party admin console
	// (authorization_code login and refresh rotation alike), deliver the refresh
	// token as an HttpOnly cookie and strip it from the JSON body so it is never
	// readable by JavaScript. The access token stays a Bearer token in the body.
	if response != nil && response.RefreshToken != "" && h.refreshCookie.handles(clientID) {
		h.writeRefreshCookie(w, response.RefreshToken)
		response.RefreshToken = ""
	}

	writeJSON(w, response)
}

// GET/POST /oauth/userinfo
// setNoStore marks a response as non-cacheable. Token, introspection, userinfo,
// and revocation responses carry sensitive material (tokens, token metadata,
// PII) and MUST NOT be cached by browsers or intermediaries (RFC 6749 §5.1,
// RFC 7662 §4, OIDC Core §5.3.2).
func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (h *OAuthHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeOAuthError(w, "invalid_token", "invalid or missing token", http.StatusUnauthorized)
		return
	}

	// Get client ID from token claims.
	// M-07 fix: use the typed contextkeys.JWTClaimsKey constant instead of the
	// raw string "jwt_claims".  A typed key prevents accidental collisions with
	// other packages that might store a value under the same string key.
	claims, ok := r.Context().Value(contextkeys.JWTClaimsKey).(*auth.AccessTokenClaims)
	clientID := ""
	if ok && len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}

	response, err := h.oauthService.GetUserInfo(r.Context(), userID, clientID)
	if err != nil {
		// HIGH-01 fix: do not leak internal error details.
		writeOAuthError(w, "server_error", "an internal error occurred", http.StatusInternalServerError)
		return
	}

	writeJSON(w, response)
}

// POST /oauth/introspect
func (h *OAuthHandler) Introspect(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	// G120: cap the request body to 1 MB before any form or JSON decode.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req dto.IntrospectRequest
	contentType := r.Header.Get("Content-Type")

	// Support both JSON and form-urlencoded formats
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, "invalid_request", "failed to parse JSON body", http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, "invalid_request", "failed to parse form", http.StatusBadRequest)
			return
		}
		req = dto.IntrospectRequest{
			Token:        r.FormValue("token"),
			ClientID:     r.FormValue("client_id"),
			ClientSecret: r.FormValue("client_secret"),
		}
	}

	// Extract client credentials (from header or body)
	clientID, clientSecret := extractClientCredentials(r)
	if req.ClientID != "" {
		clientID = req.ClientID
	}
	if req.ClientSecret != "" {
		clientSecret = req.ClientSecret
	}

	// Client authentication required
	if clientID == "" {
		writeOAuthError(w, "invalid_client", "client authentication required", http.StatusUnauthorized)
		return
	}

	if req.Token == "" {
		writeOAuthError(w, "invalid_request", "token is required", http.StatusBadRequest)
		return
	}

	// Validate client credentials
	_, err := h.appService.ValidateClientCredentials(r.Context(), clientID, clientSecret)
	if err != nil {
		writeOAuthError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		return
	}

	// L2 fix: pass the authenticated caller's own client_id so Introspect can
	// bind the response to it — a client should not learn the full claim set
	// of a token that was not issued to/for it.
	response, err := h.oauthService.Introspect(r.Context(), req.Token, clientID)
	if err != nil {
		writeJSON(w, dto.IntrospectResponse{Active: false})
		return
	}

	writeJSON(w, response)
}

// POST /oauth/revoke
func (h *OAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	// G120: cap the request body to 1 MB before any form or JSON decode.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req dto.RevokeRequest
	contentType := r.Header.Get("Content-Type")

	// Support both JSON and form-urlencoded formats
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusOK) // RFC 7009: always return 200
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusOK) // RFC 7009: always return 200
			return
		}
		req = dto.RevokeRequest{
			Token:         r.FormValue("token"),
			TokenTypeHint: r.FormValue("token_type_hint"),
			ClientID:      r.FormValue("client_id"),
			ClientSecret:  r.FormValue("client_secret"),
		}
	}

	// Path 1: user authenticated via Bearer token (OptionalAuthMiddleware sets the
	// context).  Self-revocation: the user's own identity is known.
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if ok {
		// RFC 7009: always return 200 for revocation, even on error.
		// No requestingClientID here — the caller authenticated as a user via
		// Bearer token, not as a client (L3 ownership check applies only to
		// the client-credential path below).
		_ = h.oauthService.Revoke(r.Context(), req.Token, userID, "")
		w.WriteHeader(http.StatusOK)
		return
	}

	// NEW-04 fix: Path 2 — client credential authentication for confidential
	// clients that need to revoke a token they issued (RFC 7009 §2.1).
	//
	// This enables server-side applications to revoke tokens on behalf of users
	// without requiring the user's own Bearer token to be present in the request.
	// Credentials are extracted from the Authorization header (Basic Auth) first,
	// then from the form/JSON body — consistent with other authenticated endpoints.
	clientID, clientSecret := extractClientCredentials(r)
	// Merge with request body fields in case the form was parsed before this point.
	if clientID == "" && req.ClientID != "" {
		clientID = req.ClientID
		clientSecret = req.ClientSecret
	}
	if clientID != "" {
		if _, err := h.appService.ValidateClientCredentials(r.Context(), clientID, clientSecret); err != nil {
			// Invalid credentials for an identified client: reject per RFC 7009 §2.2.1.
			writeOAuthError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
			return
		}
		// Valid client — revoke the token (userID=0: no specific user context).
		// L3 fix: pass clientID so Revoke can verify the presented token
		// actually belongs to this client before blacklisting its JTI (a
		// client must not be able to revoke a token it does not own).
		_ = h.oauthService.Revoke(r.Context(), req.Token, 0, clientID)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Path 3: no credentials of any kind.  Return 200 without revoking to
	// prevent token enumeration (RFC 7009 §2.2: always respond with HTTP 200).
	w.WriteHeader(http.StatusOK)
}

// GET/POST /oauth/logout (End Session)
// C-01 fix: post_logout_redirect_uri is now validated against the client's
// registered redirect URIs before being honoured.  Without a verifiable client
// the redirect is silently dropped and a JSON response is returned instead.
func (h *OAuthHandler) EndSession(w http.ResponseWriter, r *http.Request) {
	// Get optional parameters
	var postLogoutRedirectURI string
	var idTokenHint string
	var state string
	var clientID string

	if r.Method == http.MethodGet {
		postLogoutRedirectURI = r.URL.Query().Get("post_logout_redirect_uri")
		idTokenHint = r.URL.Query().Get("id_token_hint")
		state = r.URL.Query().Get("state")
		clientID = r.URL.Query().Get("client_id")
	} else {
		// G120: cap POST body before parsing form fields.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		_ = r.ParseForm()
		postLogoutRedirectURI = r.FormValue("post_logout_redirect_uri")
		idTokenHint = r.FormValue("id_token_hint")
		state = r.FormValue("state")
		clientID = r.FormValue("client_id")
	}

	// If user is authenticated, revoke their tokens
	if userID, ok := middleware.GetUserIDFromContext(r.Context()); ok {
		_ = h.oauthService.Revoke(r.Context(), "", userID, "")
	}

	// M-06 fix: when an id_token_hint is supplied and no explicit client_id is
	// present, extract the client_id from the token's audience claim.
	//
	// Verification strategy (OpenID Connect Core §17.4):
	//   1. Attempt full signature verification via VerifyIDToken.  If the token
	//      is valid (or merely expired but otherwise well-formed), trust its
	//      audience claim — a signed audience cannot be spoofed.
	//   2. If verification fails for any reason other than expiry (e.g. wrong
	//      signature, malformed structure), discard the hint entirely rather
	//      than fall back to unverified parsing.  This prevents an attacker
	//      from forging an audience value to pass redirect URI validation.
	if clientID == "" && idTokenHint != "" {
		if h.tokenService != nil {
			if claims, err := h.tokenService.VerifyIDToken(idTokenHint); err == nil {
				// Fully valid (non-expired) token — use the verified audience.
				if len(claims.Audience) > 0 {
					clientID = claims.Audience[0]
				}
			} else if isExpiredTokenError(err) {
				// Expired but structurally valid — the audience is trustworthy
				// even though the token can no longer be used for authentication.
				clientID = extractClientIDFromTokenHint(idTokenHint)
			}
			// Any other error (bad signature, malformed) → clientID stays "".
		} else {
			// tokenService not wired (e.g. tests) — fall back to unverified
			// extraction, which is safe because it is used only for redirect
			// URI validation and not for authentication decisions.
			clientID = extractClientIDFromTokenHint(idTokenHint)
		}
	}

	// C-01 fix: Only redirect to a URI that is registered for the identified
	// client.  If we cannot identify the client, or the URI fails validation,
	// fall through and return the JSON success response instead of redirecting.
	if postLogoutRedirectURI != "" && clientID != "" {
		app, err := h.appService.GetByClientID(r.Context(), clientID)
		if err == nil {
			// NEW-02 fix: pass h.httpsRequired so HTTP post_logout_redirect_uris
			// are rejected when the server runs under HTTPS.
			if err := auth.ValidateRedirectURI(postLogoutRedirectURI, app.RedirectURIs, h.httpsRequired); err == nil {
				redirectURL, parseErr := url.Parse(postLogoutRedirectURI)
				if parseErr == nil {
					if state != "" {
						query := redirectURL.Query()
						query.Set("state", state)
						redirectURL.RawQuery = query.Encode()
					}
					http.Redirect(w, r, redirectURL.String(), http.StatusFound)
					return
				}
			}
		}
	}

	// Return success response for API clients
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"message": "logout successful",
	})
}

// isExpiredTokenError returns true when err is an ErrTokenExpired sentinel,
// meaning the token's structure and signature are valid but its exp has passed.
// Used by EndSession to decide whether to trust the audience claim from an
// id_token_hint that is no longer fresh (M-06).
func isExpiredTokenError(err error) bool {
	return errors.Is(err, auth.ErrTokenExpired)
}

// extractClientIDFromTokenHint parses the payload section of a JWT
// (without verifying the signature) and returns the first audience value.
// It is used only to identify which client owns an id_token_hint so that
// post_logout_redirect_uri can be validated against that client's registrations.
func extractClientIDFromTokenHint(tokenHint string) string {
	parts := strings.SplitN(tokenHint, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	// JWT payloads use base64url encoding without padding.
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Aud interface{} `json:"aud"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}
	switch v := claims.Aud.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// GET /.well-known/openid-configuration
func (h *OAuthHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	config := h.oauthService.GetOpenIDConfiguration(h.issuer)
	if len(h.dpopAlgs) > 0 {
		config.DPoPSigningAlgValuesSupported = h.dpopAlgs
	}
	if len(h.extraGrantTypes) > 0 {
		config.GrantTypesSupported = append(config.GrantTypesSupported, h.extraGrantTypes...)
	}
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, config)
}

// GET /.well-known/jwks.json
func (h *OAuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.oauthService.GetJWKS()
	body, err := json.Marshal(jwks)
	if err != nil {
		writeError(w, "could not serialize JWKS", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// Let resource servers cache the key set instead of refetching on every
	// token verification (RFC-002). The max-age is kept modest so a rotated key
	// is picked up promptly; a verifier should also refetch on an unknown kid.
	if h.jwksCacheMaxAge > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", h.jwksCacheMaxAge))
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}

	// A strong ETag over the key set lets a verifier revalidate cheaply: the
	// ETag changes when keys rotate, and an unchanged set returns 304 with no
	// body. RFC 7232.
	etag := jwksETag(body)
	w.Header().Set("ETag", etag)
	if ifNoneMatchSatisfied(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if _, werr := w.Write(body); werr != nil {
		logger.Warnf("JWKS: failed to write response: %v", werr)
	}
}

// jwksETag returns a strong ETag (quoted) over the serialized key set.
func jwksETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// ifNoneMatchSatisfied reports whether an If-None-Match header matches the
// current ETag (handles a comma-separated list and the "*" wildcard).
func ifNoneMatchSatisfied(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	for _, candidate := range strings.Split(header, ",") {
		c := strings.TrimSpace(candidate)
		c = strings.TrimPrefix(c, "W/") // weak validators compare equal on value
		if c == etag {
			return true
		}
	}
	return false
}

func extractClientCredentials(r *http.Request) (clientID, clientSecret string) {
	// Try Basic Auth first
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return parts[0], parts[1]
			}
		}
	}

	// Fall back to form values
	if err := r.ParseForm(); err == nil {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	return clientID, clientSecret
}

func writeOAuthError(w http.ResponseWriter, errorCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, dto.OAuthErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}
