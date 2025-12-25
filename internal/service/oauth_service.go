package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/socrate-auth/go-oauth/internal/dto"
	"github.com/socrate-auth/go-oauth/internal/repository"
	"github.com/socrate-auth/go-oauth/internal/shared/auth"
)

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
}

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
	}
}

func (s *oauthService) Authorize(ctx context.Context, req dto.AuthorizeRequest, userID uint) (string, error) {
	// Validate response type
	if !isValidResponseType(req.ResponseType) {
		return "", ErrInvalidResponseType
	}

	// Find app by client ID
	app, err := s.appRepo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return "", ErrAppNotFound
	}

	// Validate redirect URI
	if !app.HasRedirectURI(req.RedirectURI) {
		return "", ErrInvalidRedirectURI
	}

	// Validate scope
	if err := validateScope(req.Scope); err != nil {
		return "", err
	}

	// Get user
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return "", ErrUserNotFound
	}

	// Get user's role for the app
	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, userID, app.ID)
	if err != nil {
		return "", ErrRoleNotFound
	}

	// Get all user's app roles
	appRoles, _ := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if appRoles == nil {
		appRoles = make(map[string]string)
	}

	// Generate authorization code
	code, err := s.codeStore.GenerateCode(
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
		return "", err
	}

	return code, nil
}

func (s *oauthService) Token(ctx context.Context, req dto.TokenRequest, clientID, clientSecret string) (*dto.TokenResponse, error) {
	switch req.GrantType {
	case "authorization_code":
		return s.handleAuthorizationCodeGrant(ctx, req, clientID, clientSecret)
	case "refresh_token":
		return s.handleRefreshTokenGrant(ctx, req, clientID)
	case "client_credentials":
		return s.handleClientCredentialsGrant(ctx, req, clientID, clientSecret)
	default:
		return nil, ErrInvalidGrantType
	}
}

func (s *oauthService) handleAuthorizationCodeGrant(ctx context.Context, req dto.TokenRequest, clientID, clientSecret string) (*dto.TokenResponse, error) {
	// Redeem the code
	authCode := s.codeStore.RedeemCode(req.Code)
	if authCode == nil {
		return nil, ErrInvalidCode
	}

	// Verify client ID matches
	if authCode.ClientID != clientID {
		return nil, ErrInvalidCode
	}

	// Verify redirect URI matches
	if authCode.RedirectURI != req.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	// Verify PKCE if used
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, ErrPKCERequired
		}
		if err := auth.VerifyPKCE(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			return nil, ErrPKCEVerificationFail
		}
	}

	// Get the app (for non-public clients, verify secret)
	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrAppNotFound
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
		return nil, ErrUserNotFound
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
		return nil, err
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
		return nil, ErrInvalidToken
	}

	// Verify client ID matches
	if len(claims.Audience) > 0 && claims.Audience[0] != clientID {
		return nil, ErrInvalidToken
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check token version
	if user.TokenVersion != claims.Ver {
		return nil, ErrInvalidToken
	}

	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrAppNotFound
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		return nil, ErrRoleNotFound
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
		return nil, err
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
		return nil, ErrInvalidCredentials
	}

	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrAppNotFound
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
		return nil, err
	}

	return &dto.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.tokenService.GetAccessTokenTTL().Seconds()),
		Scope:       scope,
	}, nil
}

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

func (s *oauthService) Revoke(ctx context.Context, token string, userID uint) error {
	return s.userRepo.IncrementTokenVersion(ctx, userID)
}

func (s *oauthService) GetUserInfo(ctx context.Context, userID uint, clientID string) (*dto.UserInfoResponse, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
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
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "preferred_username", "role", "app_roles"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
	}
}

func (s *oauthService) GetJWKS() dto.JWKS {
	return s.keyManager.GetJWKS()
}

func isValidResponseType(responseType string) bool {
	validTypes := map[string]bool{
		"code":         true,
		"token":        true,
		"id_token":     true,
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
			return ErrInvalidScope
		}
	}
	return nil
}
