package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/service"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

type OAuthHandler struct {
	oauthService    service.OAuthService
	authService     service.AuthService
	appService      service.AppService
	templateService *service.TemplateService
	issuer          string
}

func NewOAuthHandler(
	oauthService service.OAuthService,
	authService service.AuthService,
	appService service.AppService,
	templateService *service.TemplateService,
	issuer string,
) *OAuthHandler {
	return &OAuthHandler{
		oauthService:    oauthService,
		authService:     authService,
		appService:      appService,
		templateService: templateService,
		issuer:          issuer,
	}
}

// GET /oauth/authorize
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Parse OAuth parameters
	req := dto.AuthorizeRequest{
		ResponseType:        r.URL.Query().Get("response_type"),
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
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

	// Validate redirect URI
	if req.RedirectURI == "" || !app.HasRedirectURI(req.RedirectURI) {
		h.renderOAuthError(w, "invalid_request", "Invalid or missing redirect_uri", "")
		return
	}

	// Check if user is authenticated
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		// Render login page
		h.templateService.RenderLogin(w, service.LoginPageData{
			AppName:             app.Name,
			ClientID:            req.ClientID,
			RedirectURI:         req.RedirectURI,
			ResponseType:        req.ResponseType,
			Scope:               req.Scope,
			State:               req.State,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			Nonce:               req.Nonce,
		})
		return
	}

	// User is authenticated - generate authorization code
	if req.ResponseType == "" {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "invalid_request", "response_type is required")
		return
	}

	code, err := h.oauthService.Authorize(r.Context(), req, userID)
	if err != nil {
		switch err {
		case service.ErrInvalidRedirectURI:
			h.redirectWithError(w, r, req.RedirectURI, req.State, "invalid_request", "invalid redirect_uri")
		case service.ErrAppNotFound:
			h.redirectWithError(w, r, req.RedirectURI, req.State, "invalid_client", "client not found")
		case service.ErrRoleNotFound:
			h.redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "user does not have access to this application")
		default:
			h.redirectWithError(w, r, req.RedirectURI, req.State, "server_error", err.Error())
		}
		return
	}

	// Build redirect URL with code
	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "failed to parse redirect URI")
		return
	}

	query := redirectURL.Query()
	query.Set("code", code)
	if req.State != "" {
		query.Set("state", req.State)
	}
	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// POST /oauth/authorize - Handle login form submission
func (h *OAuthHandler) AuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderOAuthError(w, "invalid_request", "Failed to parse form", "")
		return
	}

	// Extract OAuth parameters from form
	req := dto.AuthorizeRequest{
		ResponseType:        r.FormValue("response_type"),
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Get app details
	app, err := h.appService.GetByClientID(r.Context(), req.ClientID)
	if err != nil {
		h.renderOAuthError(w, "invalid_client", "Unknown client", "")
		return
	}

	// Validate redirect URI
	if req.RedirectURI == "" || !app.HasRedirectURI(req.RedirectURI) {
		h.renderOAuthError(w, "invalid_request", "Invalid redirect_uri", "")
		return
	}

	// Helper to re-render login with error
	renderLoginError := func(errorMsg string) {
		h.templateService.RenderLogin(w, service.LoginPageData{
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
		})
	}

	// Validate credentials
	if email == "" || password == "" {
		renderLoginError("Email and password are required")
		return
	}

	// Authenticate user
	loginReq := dto.LoginRequest{
		Email:       email,
		Password:    password,
		AppClientID: req.ClientID,
	}

	loginResp, err := h.authService.Login(r.Context(), loginReq)
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			renderLoginError("Invalid email or password")
		case service.ErrUserNotVerified:
			renderLoginError("Please verify your email address first")
		case service.ErrAccountLocked:
			renderLoginError("Your account has been locked. Please try again later")
		case service.ErrRoleNotFound:
			renderLoginError("You do not have access to this application")
		default:
			renderLoginError("Login failed. Please try again")
		}
		return
	}

	// Generate authorization code
	code, err := h.oauthService.Authorize(r.Context(), req, loginResp.UserID)
	if err != nil {
		switch err {
		case service.ErrRoleNotFound:
			renderLoginError("You do not have access to this application")
		default:
			renderLoginError("Failed to authorize. Please try again")
		}
		return
	}

	// Build redirect URL with code
	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		renderLoginError("Failed to process redirect")
		return
	}

	query := redirectURL.Query()
	query.Set("code", code)
	if req.State != "" {
		query.Set("state", req.State)
	}
	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// renderOAuthError renders the error page
func (h *OAuthHandler) renderOAuthError(w http.ResponseWriter, errorCode, message, returnURL string) {
	h.templateService.RenderError(w, service.ErrorPageData{
		Title:     "Authorization Error",
		Message:   message,
		ErrorCode: errorCode,
		ReturnURL: returnURL,
	})
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
	// Set no-cache headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "failed to parse form", http.StatusBadRequest)
		return
	}

	// Extract client credentials
	clientID, clientSecret := extractClientCredentials(r)

	req := dto.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RefreshToken: r.FormValue("refresh_token"),
		CodeVerifier: r.FormValue("code_verifier"),
		Scope:        r.FormValue("scope"),
	}

	if req.GrantType == "" {
		writeOAuthError(w, "invalid_request", "grant_type is required", http.StatusBadRequest)
		return
	}

	response, err := h.oauthService.Token(r.Context(), req, clientID, clientSecret)
	if err != nil {
		switch err {
		case service.ErrInvalidGrantType:
			writeOAuthError(w, "unsupported_grant_type", "unsupported grant type", http.StatusBadRequest)
		case service.ErrInvalidCode:
			writeOAuthError(w, "invalid_grant", "invalid authorization code", http.StatusBadRequest)
		case service.ErrCodeExpired:
			writeOAuthError(w, "invalid_grant", "authorization code expired", http.StatusBadRequest)
		case service.ErrInvalidCredentials:
			writeOAuthError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		case service.ErrPKCEVerificationFail:
			writeOAuthError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		case service.ErrInvalidToken:
			writeOAuthError(w, "invalid_grant", "invalid refresh token", http.StatusBadRequest)
		default:
			writeOAuthError(w, "server_error", err.Error(), http.StatusInternalServerError)
		}
		return
	}

	json.NewEncoder(w).Encode(response)
}

// GET/POST /oauth/userinfo
func (h *OAuthHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeOAuthError(w, "invalid_token", "invalid or missing token", http.StatusUnauthorized)
		return
	}

	// Get client ID from token claims
	claims, ok := r.Context().Value("jwt_claims").(*auth.AccessTokenClaims)
	clientID := ""
	if ok && len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}

	response, err := h.oauthService.GetUserInfo(r.Context(), userID, clientID)
	if err != nil {
		writeOAuthError(w, "server_error", err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(response)
}

// POST /oauth/introspect
func (h *OAuthHandler) Introspect(w http.ResponseWriter, r *http.Request) {
	// Client authentication required
	clientID, clientSecret := extractClientCredentials(r)
	if clientID == "" {
		writeOAuthError(w, "invalid_client", "client authentication required", http.StatusUnauthorized)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "failed to parse form", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		writeOAuthError(w, "invalid_request", "token is required", http.StatusBadRequest)
		return
	}

	// Validate client credentials (simplified - in production, check against DB)
	_ = clientSecret // TODO: Validate client secret

	response, err := h.oauthService.Introspect(r.Context(), token)
	if err != nil {
		json.NewEncoder(w).Encode(dto.IntrospectResponse{Active: false})
		return
	}

	json.NewEncoder(w).Encode(response)
}

// POST /oauth/revoke
func (h *OAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		// Parse form for token-based revocation
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusOK) // RFC 7009: always return 200
			return
		}
		// For now, just return success
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := h.oauthService.Revoke(r.Context(), "", userID); err != nil {
		// RFC 7009: always return 200 for revocation
	}

	w.WriteHeader(http.StatusOK)
}

// GET/POST /oauth/logout (End Session)
func (h *OAuthHandler) EndSession(w http.ResponseWriter, r *http.Request) {
	// Get optional parameters
	var postLogoutRedirectURI string
	var idTokenHint string
	var state string

	if r.Method == http.MethodGet {
		postLogoutRedirectURI = r.URL.Query().Get("post_logout_redirect_uri")
		idTokenHint = r.URL.Query().Get("id_token_hint")
		state = r.URL.Query().Get("state")
	} else {
		_ = r.ParseForm()
		postLogoutRedirectURI = r.FormValue("post_logout_redirect_uri")
		idTokenHint = r.FormValue("id_token_hint")
		state = r.FormValue("state")
	}

	// If user is authenticated, revoke their tokens
	if userID, ok := middleware.GetUserIDFromContext(r.Context()); ok {
		_ = h.oauthService.Revoke(r.Context(), "", userID)
	}

	// Validate id_token_hint if provided
	if idTokenHint != "" {
		// TODO: Validate the id_token_hint matches the current session
	}

	// If post_logout_redirect_uri is provided, redirect there
	if postLogoutRedirectURI != "" {
		// TODO: Validate the redirect URI is registered for the client
		redirectURL, err := url.Parse(postLogoutRedirectURI)
		if err == nil {
			if state != "" {
				query := redirectURL.Query()
				query.Set("state", state)
				redirectURL.RawQuery = query.Encode()
			}
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return
		}
	}

	// Return success response for API clients
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "logout successful",
	})
}

// GET /.well-known/openid-configuration
func (h *OAuthHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	config := h.oauthService.GetOpenIDConfiguration(h.issuer)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// GET /.well-known/jwks.json
func (h *OAuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.oauthService.GetJWKS()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
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
	json.NewEncoder(w).Encode(dto.OAuthErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// GET /auth/accept-invite - Show the accept invite form
func (h *OAuthHandler) AcceptInvitePage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h.templateService.RenderAcceptInvite(w, service.AcceptInvitePageData{
			Valid: false,
			Error: "Missing invitation token",
		})
		return
	}

	// Validate the token
	validation, err := h.authService.ValidateInviteToken(r.Context(), token)
	if err != nil || !validation.Valid {
		h.templateService.RenderAcceptInvite(w, service.AcceptInvitePageData{
			Valid: false,
			Error: "This invitation link is invalid or has expired",
		})
		return
	}

	h.templateService.RenderAcceptInvite(w, service.AcceptInvitePageData{
		Token:   token,
		Email:   validation.Email,
		AppName: validation.AppName,
		Valid:   true,
	})
}

// POST /auth/accept-invite - Process the accept invite form
func (h *OAuthHandler) AcceptInviteSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.templateService.RenderAcceptInvite(w, service.AcceptInvitePageData{
			Valid: false,
			Error: "Failed to parse form",
		})
		return
	}

	token := r.FormValue("token")
	name := r.FormValue("name")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	// Validate the token first to get app info for error display
	validation, err := h.authService.ValidateInviteToken(r.Context(), token)
	if err != nil || !validation.Valid {
		h.templateService.RenderAcceptInvite(w, service.AcceptInvitePageData{
			Valid: false,
			Error: "This invitation link is invalid or has expired",
		})
		return
	}

	// Render with error helper
	renderError := func(errMsg string) {
		h.templateService.RenderAcceptInvite(w, service.AcceptInvitePageData{
			Token:   token,
			Email:   validation.Email,
			Name:    name,
			AppName: validation.AppName,
			Valid:   true,
			Error:   errMsg,
		})
	}

	// Validate inputs
	if name == "" {
		renderError("Name is required")
		return
	}

	if password == "" {
		renderError("Password is required")
		return
	}

	if len(password) < 8 {
		renderError("Password must be at least 8 characters")
		return
	}

	if password != confirmPassword {
		renderError("Passwords do not match")
		return
	}

	// Accept the invite
	_, err = h.authService.AcceptInvite(r.Context(), token, name, password)
	if err != nil {
		renderError("Failed to complete setup: " + err.Error())
		return
	}

	// Show success message
	h.templateService.RenderAcceptInvite(w, service.AcceptInvitePageData{
		AppName: validation.AppName,
		Valid:   true,
		Success: "Your account has been set up successfully! You can now log in with your email and password.",
	})
}
