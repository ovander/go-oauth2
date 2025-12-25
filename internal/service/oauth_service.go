package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// OAuth service errors
var (
	ErrInvalidGrantType     = errors.New("invalid grant type")
	ErrInvalidResponseType  = errors.New("invalid response type")
	ErrInvalidScope         = errors.New("invalid scope")
	ErrInvalidCode          = errors.New("invalid authorization code")
	ErrCodeExpired          = errors.New("authorization code expired")
	ErrCodeAlreadyUsed      = errors.New("authorization code already used")
	ErrPKCERequired         = errors.New("PKCE code verifier required")
	ErrPKCEVerificationFail = errors.New("PKCE verification failed")
)

var validScopes = map[string]bool{
	"openid":         true,
	"email":          true,
	"profile":        true,
	"offline_access": true,
	"api":            true,
}

// OAuthService defines the OAuth 2.0 service interface
type OAuthService interface {
	Authorize(ctx context.Context, req dto.AuthorizeRequest, userID uint) (string, error)
	Token(ctx context.Context, req dto.TokenRequest, clientID, clientSecret string) (*dto.TokenResponse, error)
	Introspect(ctx context.Context, token string) (*dto.IntrospectResponse, error)
	Revoke(ctx context.Context, token string, userID uint) error
	GetUserInfo(ctx context.Context, userID uint, clientID string) (*dto.UserInfoResponse, error)
	GetOpenIDConfiguration(issuer string) *dto.OpenIDConfiguration
	GetJWKS() dto.JWKS
}

type oauthService struct {
	userRepo        repository.UserRepository
	appRepo         repository.AppRepository
	userAppRoleRepo repository.UserAppRoleRepository
	codeStore       *auth.CodeStore
	tokenService    *auth.TokenService
	keyManager      *auth.KeyManager
	issuer          string
	requireHTTPS    bool
}

// OAuthServiceConfig holds OAuth service configuration
type OAuthServiceConfig struct {
	RequireHTTPS bool
}

// NewOAuthService creates a new OAuth service
func NewOAuthService(
	userRepo repository.UserRepository,
	appRepo repository.AppRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	codeStore *auth.CodeStore,
	tokenService *auth.TokenService,
	keyManager *auth.KeyManager,
	issuer string,
) OAuthService {
	return &oauthService{
		userRepo:        userRepo,
		appRepo:         appRepo,
		userAppRoleRepo: userAppRoleRepo,
		codeStore:       codeStore,
		tokenService:    tokenService,
		keyManager:      keyManager,
		issuer:          issuer,
		requireHTTPS:    strings.HasPrefix(issuer, "https://"),
	}
}

// NewOAuthServiceWithConfig creates a new OAuth service with configuration
func NewOAuthServiceWithConfig(
	userRepo repository.UserRepository,
	appRepo repository.AppRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	codeStore *auth.CodeStore,
	tokenService *auth.TokenService,
	keyManager *auth.KeyManager,
	issuer string,
	config OAuthServiceConfig,
) OAuthService {
	return &oauthService{
		userRepo:        userRepo,
		appRepo:         appRepo,
		userAppRoleRepo: userAppRoleRepo,
		codeStore:       codeStore,
		tokenService:    tokenService,
		keyManager:      keyManager,
		issuer:          issuer,
		requireHTTPS:    config.RequireHTTPS,
	}
}

// Authorize handles the OAuth 2.0 authorization request
func (s *oauthService) Authorize(ctx context.Context, req dto.AuthorizeRequest, userID uint) (string, error) {
	// Validate response type
	if !isValidResponseType(req.ResponseType) {
		return "", ErrInvalidResponseType
	}

	// Find app by client ID
	app, err := s.appRepo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return "", fmt.Errorf("%w: client_id=%s", ErrAppNotFound, req.ClientID)
	}

	// Validate redirect URI with enhanced security checks
	if err := auth.ValidateRedirectURI(req.RedirectURI, app.RedirectURIs, s.requireHTTPS); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidRedirectURI, err)
	}

	// Validate scope
	if err := validateScope(req.Scope); err != nil {
		return "", fmt.Errorf("invalid scope '%s': %w", req.Scope, err)
	}

	// Get user
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	// Get user's role for the app
	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, userID, app.ID)
	if err != nil {
		return "", fmt.Errorf("%w: user has no role for app_id=%d", ErrRoleNotFound, app.ID)
	}

	// Get all user's app roles
	appRoles, _ := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if appRoles == nil {
		appRoles = make(map[string]string)
	}

	// Generate authorization code
	code, err := s.codeStore.GenerateCode(
		ctx,
		userID,
		app.ID,
		req.ClientID,
		req.RedirectURI,
		req.Scope,
		req.Nonce,
		req.CodeChallenge,
		req.CodeChallengeMethod,
		string(userAppRole.Role),
		appRoles,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	return code, nil
}

// Token handles the OAuth 2.0 token request
func (s *oauthService) Token(ctx context.Context, req dto.TokenRequest, clientID, clientSecret string) (*dto.TokenResponse, error) {
	switch req.GrantType {
	case "authorization_code":
		return s.handleAuthorizationCodeGrant(ctx, req, clientID, clientSecret)
	case "refresh_token":
		return s.handleRefreshTokenGrant(ctx, req, clientID)
	case "client_credentials":
		return s.handleClientCredentialsGrant(ctx, req, clientID, clientSecret)
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidGrantType, req.GrantType)
	}
}

func (s *oauthService) handleAuthorizationCodeGrant(ctx context.Context, req dto.TokenRequest, clientID, clientSecret string) (*dto.TokenResponse, error) {
	// Redeem the code atomically
	authCode, err := s.codeStore.RedeemCode(ctx, req.Code)
	if err != nil || authCode == nil {
		return nil, ErrInvalidCode
	}

	// Verify client ID matches
	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("%w: client_id mismatch", ErrInvalidCode)
	}

	// Verify redirect URI matches
	if authCode.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("%w: redirect_uri=%s", ErrInvalidRedirectURI, req.RedirectURI)
	}

	// Verify PKCE if used
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, ErrPKCERequired
		}
		if err := auth.VerifyPKCE(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPKCEVerificationFail, err)
		}
	}

	// Get the app (for non-public clients, verify secret)
	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, clientID)
	}

	// If client secret is provided, verify it
	if clientSecret != "" {
		if !auth.CheckClientSecret(clientSecret, app.ClientSecretHash) {
			return nil, ErrInvalidCredentials
		}
	}

	// Get the user
	user, err := s.userRepo.FindByID(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: user_id=%d", ErrUserNotFound, authCode.UserID)
	}

	// Generate tokens
	now := time.Now()
	tokenSet, err := s.tokenService.GenerateTokenSet(
		user,
		app,
		authCode.Role,
		authCode.Scope,
		authCode.AppRoles,
		authCode.Nonce,
		now.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token set: %w", err)
	}

	roles := []string{}
	if authCode.Role != "" {
		roles = append(roles, authCode.Role)
	}

	return &dto.TokenResponse{
		AccessToken:  tokenSet.AccessToken,
		RefreshToken: tokenSet.RefreshToken,
		IDToken:      tokenSet.IDToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokenSet.ExpiresIn,
		Scope:        authCode.Scope,
		Roles:        roles,
		AppRoles:     authCode.AppRoles,
	}, nil
}

func (s *oauthService) handleRefreshTokenGrant(ctx context.Context, req dto.TokenRequest, clientID string) (*dto.TokenResponse, error) {
	claims, err := s.tokenService.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Verify client ID matches
	if len(claims.Audience) > 0 && claims.Audience[0] != clientID {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid subject claim", ErrInvalidToken)
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return nil, fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	// Check token version (revocation check)
	if user.TokenVersion != claims.Ver {
		return nil, fmt.Errorf("%w: token has been revoked", ErrInvalidToken)
	}

	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, clientID)
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: user has no role for app", ErrRoleNotFound)
	}

	appRoles, _ := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if appRoles == nil {
		appRoles = make(map[string]string)
	}

	tokenSet, err := s.tokenService.GenerateTokenSet(
		user,
		app,
		string(userAppRole.Role),
		claims.Scope,
		appRoles,
		"",
		claims.AuthTime,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token set: %w", err)
	}

	roles := []string{string(userAppRole.Role)}

	return &dto.TokenResponse{
		AccessToken:  tokenSet.AccessToken,
		RefreshToken: tokenSet.RefreshToken,
		IDToken:      tokenSet.IDToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokenSet.ExpiresIn,
		Scope:        claims.Scope,
		Roles:        roles,
		AppRoles:     appRoles,
	}, nil
}

func (s *oauthService) handleClientCredentialsGrant(ctx context.Context, req dto.TokenRequest, clientID, clientSecret string) (*dto.TokenResponse, error) {
	if clientSecret == "" {
		return nil, fmt.Errorf("%w: client_secret required for client_credentials grant", ErrInvalidCredentials)
	}

	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, clientID)
	}

	if !auth.CheckClientSecret(clientSecret, app.ClientSecretHash) {
		return nil, ErrInvalidCredentials
	}

	scope := req.Scope
	if scope == "" {
		scope = "api"
	}

	accessToken, err := s.tokenService.GenerateClientCredentialsToken(app, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &dto.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.tokenService.GetAccessTokenTTL().Seconds()),
		Scope:       scope,
	}, nil
}

// Introspect handles token introspection (RFC 7662)
func (s *oauthService) Introspect(ctx context.Context, token string) (*dto.IntrospectResponse, error) {
	claims, err := s.tokenService.VerifyAccessToken(token)
	if err != nil {
		return &dto.IntrospectResponse{Active: false}, nil
	}

	userID, _ := strconv.ParseUint(claims.Subject, 10, 64)
	user, err := s.userRepo.FindByID(ctx, uint(userID))

	username := ""
	if err == nil {
		username = user.Email
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}

	return &dto.IntrospectResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  clientID,
		Username:  username,
		TokenType: "Bearer",
		Exp:       claims.ExpiresAt.Unix(),
		Iat:       claims.IssuedAt.Unix(),
		Sub:       claims.Subject,
	}, nil
}

// Revoke handles token revocation (RFC 7009)
func (s *oauthService) Revoke(ctx context.Context, token string, userID uint) error {
	if err := s.userRepo.IncrementTokenVersion(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke tokens: %w", err)
	}
	return nil
}

// GetUserInfo handles the OpenID Connect UserInfo endpoint
func (s *oauthService) GetUserInfo(ctx context.Context, userID uint, clientID string) (*dto.UserInfoResponse, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	appRoles, _ := s.userAppRoleRepo.GetUserRolesMap(ctx, userID)
	if appRoles == nil {
		appRoles = make(map[string]string)
	}

	role := ""
	if clientID != "" {
		role = appRoles[clientID]
	}

	return &dto.UserInfoResponse{
		Sub:               strconv.FormatUint(uint64(user.ID), 10),
		Email:             user.Email,
		EmailVerified:     user.IsVerified,
		Name:              user.Name,
		PreferredUsername: user.Email,
		Role:              role,
		AppRoles:          appRoles,
	}, nil
}

// GetOpenIDConfiguration returns the OpenID Connect discovery document
func (s *oauthService) GetOpenIDConfiguration(issuer string) *dto.OpenIDConfiguration {
	return &dto.OpenIDConfiguration{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth/authorize",
		TokenEndpoint:                     issuer + "/oauth/token",
		UserinfoEndpoint:                  issuer + "/oauth/userinfo",
		JwksURI:                           issuer + "/.well-known/jwks.json",
		IntrospectionEndpoint:             issuer + "/oauth/introspect",
		RevocationEndpoint:                issuer + "/oauth/revoke",
		ResponseTypesSupported:            []string{"code", "token", "id_token", "code id_token"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "email", "profile", "offline_access", "api"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "nbf", "email", "email_verified", "name", "preferred_username", "role", "app_roles", "token_version"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
	}
}

// GetJWKS returns the JSON Web Key Set
func (s *oauthService) GetJWKS() dto.JWKS {
	return s.keyManager.GetJWKS()
}

func isValidResponseType(responseType string) bool {
	validTypes := map[string]bool{
		"code":          true,
		"token":         true,
		"id_token":      true,
		"code id_token": true,
	}
	return validTypes[responseType]
}

func validateScope(scope string) error {
	if scope == "" {
		return nil
	}

	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		if !validScopes[s] {
			return fmt.Errorf("%w: unknown scope '%s'", ErrInvalidScope, s)
		}
	}
	return nil
}
