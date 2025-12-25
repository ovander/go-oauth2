package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

// Token-related errors
var (
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenNotYetValid   = errors.New("token is not yet valid")
	ErrTokenInvalidType   = errors.New("invalid token type")
	ErrTokenMalformed     = errors.New("malformed token")
	ErrTokenSignature     = errors.New("invalid token signature")
	ErrTokenClaimsInvalid = errors.New("invalid token claims")
)

// TokenService handles JWT token generation and verification
type TokenService struct {
	keyManager      *KeyManager
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	emailTokenTTL   time.Duration
	resetTokenTTL   time.Duration
	inviteTokenTTL  time.Duration
}

// TokenConfig holds token configuration
type TokenConfig struct {
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	EmailTokenTTL   time.Duration
	ResetTokenTTL   time.Duration
	InviteTokenTTL  time.Duration
}

// NewTokenService creates a new token service
func NewTokenService(keyManager *KeyManager, config TokenConfig) *TokenService {
	return &TokenService{
		keyManager:      keyManager,
		issuer:          config.Issuer,
		accessTokenTTL:  config.AccessTokenTTL,
		refreshTokenTTL: config.RefreshTokenTTL,
		emailTokenTTL:   config.EmailTokenTTL,
		resetTokenTTL:   config.ResetTokenTTL,
		inviteTokenTTL:  config.InviteTokenTTL,
	}
}

// AccessTokenClaims represents access token claims
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Scope        string            `json:"scope,omitempty"`
	Role         string            `json:"role,omitempty"`
	Type         string            `json:"type"`
	TokenVersion int               `json:"token_version,omitempty"`
	AppRoles     map[string]string `json:"app_roles,omitempty"`
	Roles        []string          `json:"roles,omitempty"`
}

// RefreshTokenClaims represents refresh token claims
type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	Scope    string            `json:"scope,omitempty"`
	Role     string            `json:"role,omitempty"`
	Ver      int               `json:"ver"`
	AuthTime int64             `json:"auth_time"`
	Type     string            `json:"type"`
	AppRoles map[string]string `json:"app_roles,omitempty"`
	Roles    []string          `json:"roles,omitempty"`
}

// IDTokenClaims represents ID token claims (OpenID Connect)
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	Role              string `json:"role,omitempty"`
	Type              string `json:"type"`
	Nonce             string `json:"nonce,omitempty"`
	AtHash            string `json:"at_hash,omitempty"`
}

// EmailTokenClaims represents email verification/reset token claims
type EmailTokenClaims struct {
	jwt.RegisteredClaims
	Email  string `json:"email"`
	Type   string `json:"type"`
	Action string `json:"action"`
}

// InviteTokenClaims represents invite token claims
type InviteTokenClaims struct {
	jwt.RegisteredClaims
	Email     string `json:"email"`
	AppID     uint   `json:"app_id"`
	Role      string `json:"role"`
	Type      string `json:"type"`
	InvitedBy uint   `json:"invited_by"`
}

// TokenSet represents a complete set of tokens issued during authentication
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int
}

// GenerateTokenSet generates a complete token set for a user
func (ts *TokenService) GenerateTokenSet(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, nonce string, authTime int64) (*TokenSet, error) {
	now := time.Now()
	if authTime == 0 {
		authTime = now.Unix()
	}

	// Generate access token
	accessToken, err := ts.generateAccessToken(user, app, role, scope, appRoles, now)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := ts.generateRefreshToken(user, app, role, scope, appRoles, now, authTime)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Generate ID token
	idToken, err := ts.generateIDToken(user, app, nonce, now, authTime, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID token: %w", err)
	}

	return &TokenSet{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ExpiresIn:    int(ts.accessTokenTTL.Seconds()),
	}, nil
}

// generateAccessToken generates an access token with token version for revocation support
func (ts *TokenService) generateAccessToken(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, now time.Time) (string, error) {
	roles := []string{}
	if role != "" {
		roles = append(roles, role)
	}

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   strconv.FormatUint(uint64(user.ID), 10),
			Audience:  jwt.ClaimStrings{app.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now), // Token valid immediately (nbf claim)
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.accessTokenTTL)),
			ID:        uuid.New().String(),
		},
		Scope:        scope,
		Role:         role,
		Type:         "access",
		TokenVersion: user.TokenVersion, // Include token version for revocation check
		AppRoles:     appRoles,
		Roles:        roles,
	}

	return ts.signToken(claims)
}

// generateRefreshToken generates a refresh token
func (ts *TokenService) generateRefreshToken(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, now time.Time, authTime int64) (string, error) {
	roles := []string{}
	if role != "" {
		roles = append(roles, role)
	}

	claims := RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   strconv.FormatUint(uint64(user.ID), 10),
			Audience:  jwt.ClaimStrings{app.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now), // Token valid immediately (nbf claim)
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.refreshTokenTTL)),
			ID:        uuid.New().String(),
		},
		Scope:    scope,
		Role:     role,
		Ver:      user.TokenVersion,
		AuthTime: authTime,
		Type:     "refresh",
		AppRoles: appRoles,
		Roles:    roles,
	}

	return ts.signToken(claims)
}

// generateIDToken generates an OpenID Connect ID token
func (ts *TokenService) generateIDToken(user *model.User, app *model.App, nonce string, now time.Time, authTime int64, accessToken string) (string, error) {
	// Calculate at_hash (access token hash)
	atHash := ts.calculateAtHash(accessToken)

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   strconv.FormatUint(uint64(user.ID), 10),
			Audience:  jwt.ClaimStrings{app.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now), // Token valid immediately (nbf claim)
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.accessTokenTTL)),
			ID:        uuid.New().String(),
		},
		Email:             user.Email,
		EmailVerified:     user.IsVerified,
		Name:              user.Name,
		PreferredUsername: user.Email,
		AuthTime:          authTime,
		Role:              string(user.Role),
		Type:              "id_token",
		Nonce:             nonce,
		AtHash:            atHash,
	}

	return ts.signToken(claims)
}

// GenerateEmailVerificationToken generates an email verification token
func (ts *TokenService) GenerateEmailVerificationToken(email string, userID uint) (string, error) {
	now := time.Now()

	claims := EmailTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   strconv.FormatUint(uint64(userID), 10),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.emailTokenTTL)),
			ID:        uuid.New().String(),
		},
		Email:  email,
		Type:   "email_verification",
		Action: "verify",
	}

	return ts.signToken(claims)
}

// GeneratePasswordResetToken generates a password reset token
func (ts *TokenService) GeneratePasswordResetToken(email string, userID uint) (string, error) {
	now := time.Now()

	claims := EmailTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   strconv.FormatUint(uint64(userID), 10),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.resetTokenTTL)),
			ID:        uuid.New().String(),
		},
		Email:  email,
		Type:   "password_reset",
		Action: "reset",
	}

	return ts.signToken(claims)
}

// GenerateInviteToken generates an invite token
func (ts *TokenService) GenerateInviteToken(email string, appID uint, role string, invitedBy uint) (string, error) {
	now := time.Now()

	claims := InviteTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.inviteTokenTTL)),
			ID:        uuid.New().String(),
		},
		Email:     email,
		AppID:     appID,
		Role:      role,
		Type:      "invite",
		InvitedBy: invitedBy,
	}

	return ts.signToken(claims)
}

// GenerateClientCredentialsToken generates an access token for client credentials grant
func (ts *TokenService) GenerateClientCredentialsToken(app *model.App, scope string) (string, error) {
	now := time.Now()

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   fmt.Sprintf("app:%d", app.ID),
			Audience:  jwt.ClaimStrings{app.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.accessTokenTTL)),
			ID:        uuid.New().String(),
		},
		Scope: scope,
		Type:  "access",
	}

	return ts.signToken(claims)
}

// signToken signs a token with the private key
func (ts *TokenService) signToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = ts.keyManager.GetKeyID()

	return token.SignedString(ts.keyManager.GetPrivateKey())
}

// verifyToken is a generic token verification function that consolidates common logic
func (ts *TokenService) verifyToken(tokenString string, claims jwt.Claims) error {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ts.keyManager.GetPublicKey(), nil
	})

	if err != nil {
		// Provide more specific error messages
		if errors.Is(err, jwt.ErrTokenExpired) {
			return ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return ErrTokenNotYetValid
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return ErrTokenMalformed
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return ErrTokenSignature
		}
		return fmt.Errorf("token verification failed: %w", err)
	}

	if !token.Valid {
		return ErrTokenClaimsInvalid
	}

	return nil
}

// VerifyAccessToken verifies an access token and returns its claims
func (ts *TokenService) VerifyAccessToken(tokenString string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	if err := ts.verifyToken(tokenString, claims); err != nil {
		return nil, err
	}

	if claims.Type != "access" {
		return nil, fmt.Errorf("%w: expected access, got %s", ErrTokenInvalidType, claims.Type)
	}

	return claims, nil
}

// VerifyRefreshToken verifies a refresh token and returns its claims
func (ts *TokenService) VerifyRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	claims := &RefreshTokenClaims{}
	if err := ts.verifyToken(tokenString, claims); err != nil {
		return nil, err
	}

	if claims.Type != "refresh" {
		return nil, fmt.Errorf("%w: expected refresh, got %s", ErrTokenInvalidType, claims.Type)
	}

	return claims, nil
}

// VerifyEmailToken verifies an email token and returns its claims
func (ts *TokenService) VerifyEmailToken(tokenString string) (*EmailTokenClaims, error) {
	claims := &EmailTokenClaims{}
	if err := ts.verifyToken(tokenString, claims); err != nil {
		return nil, err
	}

	// Email tokens can be either email_verification or password_reset
	if claims.Type != "email_verification" && claims.Type != "password_reset" {
		return nil, fmt.Errorf("%w: expected email_verification or password_reset, got %s", ErrTokenInvalidType, claims.Type)
	}

	return claims, nil
}

// VerifyInviteToken verifies an invite token and returns its claims
func (ts *TokenService) VerifyInviteToken(tokenString string) (*InviteTokenClaims, error) {
	claims := &InviteTokenClaims{}
	if err := ts.verifyToken(tokenString, claims); err != nil {
		return nil, err
	}

	if claims.Type != "invite" {
		return nil, fmt.Errorf("%w: expected invite, got %s", ErrTokenInvalidType, claims.Type)
	}

	return claims, nil
}

// calculateAtHash calculates the access token hash for ID tokens
func (ts *TokenService) calculateAtHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	// Take left-most half of the hash
	halfHash := hash[:len(hash)/2]
	return base64.RawURLEncoding.EncodeToString(halfHash)
}

// GetAccessTokenTTL returns the access token TTL
func (ts *TokenService) GetAccessTokenTTL() time.Duration {
	return ts.accessTokenTTL
}

// GetRefreshTokenTTL returns the refresh token TTL
func (ts *TokenService) GetRefreshTokenTTL() time.Duration {
	return ts.refreshTokenTTL
}
