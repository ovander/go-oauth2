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
	oauthService service.OAuthService
	issuer       string
}

func NewOAuthHandler(oauthService service.OAuthService, issuer string) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		issuer:       issuer,
	}
}

// GET /oauth/authorize
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		// Redirect to login
		loginURL := h.issuer + "/auth/login?return_to=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
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
	}

	if req.ResponseType == "" || req.ClientID == "" || req.RedirectURI == "" {
		writeOAuthError(w, "invalid_request", "response_type, client_id, and redirect_uri are required", http.StatusBadRequest)
		return
	}

	code, err := h.oauthService.Authorize(r.Context(), req, userID)
	if err != nil {
		switch err {
		case service.ErrInvalidRedirectURI:
			writeOAuthError(w, "invalid_request", "invalid redirect_uri", http.StatusBadRequest)
		case service.ErrAppNotFound:
			writeOAuthError(w, "invalid_client", "client not found", http.StatusBadRequest)
		case service.ErrRoleNotFound:
			writeOAuthError(w, "access_denied", "user does not have access to this application", http.StatusForbidden)
		default:
			writeOAuthError(w, "server_error", err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Build redirect URL with code
	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		writeOAuthError(w, "server_error", "failed to parse redirect URI", http.StatusInternalServerError)
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
