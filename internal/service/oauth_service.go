package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/tokenexchange"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// dpopJKTFromContext returns the verified DPoP JWK thumbprint placed on the
// request context by middleware.DPoP, or "" when no valid proof was sent.
func dpopJKTFromContext(ctx context.Context) string {
	jkt, _ := ctx.Value(contextkeys.DPoPJKTKey).(string)
	return jkt
}

// requireDPoP enforces a client's per-client DPoP requirement: when app.RequireDPoP
// is set, the request must carry a verified DPoP proof (a non-empty thumbprint on
// the context). Returns ErrDPoPRequired otherwise.
func requireDPoP(ctx context.Context, app *model.App) error {
	if app.RequireDPoP && dpopJKTFromContext(ctx) == "" {
		return ErrDPoPRequired
	}
	return nil
}

// verifyRefreshDPoPBinding enforces that a DPoP-bound refresh token (cnf.jkt set)
// is presented with a DPoP proof for the same key (RFC 9449 §5). Unbound refresh
// tokens are unaffected.
func verifyRefreshDPoPBinding(ctx context.Context, cnfJKT string) error {
	if cnfJKT != "" && dpopJKTFromContext(ctx) != cnfJKT {
		return ErrDPoPKeyMismatch
	}
	return nil
}

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
	// ErrDPoPRequired indicates the client requires DPoP (RFC 9449) but the token
	// request carried no valid DPoP proof.
	ErrDPoPRequired = errors.New("DPoP proof required for this client")
	// ErrDPoPKeyMismatch indicates a DPoP-bound refresh token was presented with
	// a proof for a different key (RFC 9449 §5).
	ErrDPoPKeyMismatch = errors.New("DPoP proof key does not match the refresh token binding")
	// ErrInvalidExchangeRequest indicates a malformed RFC 8693 token-exchange
	// request (maps to invalid_request).
	ErrInvalidExchangeRequest = errors.New("invalid token-exchange request")
	// ErrStepUpRequired indicates an impersonation exchange was denied because the
	// subject's authentication is too old (EPIC-17 step-up). Maps to invalid_grant.
	ErrStepUpRequired = errors.New("impersonation requires a more recent subject authentication")
	// ErrDelegationStepUpRequired indicates a delegation exchange was denied
	// because the actor did not authenticate with MFA (EPIC-17 step-up). Maps to
	// invalid_grant.
	ErrDelegationStepUpRequired = errors.New("delegation requires the actor to have authenticated with MFA")
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
	// ExchangeToken handles an RFC 8693 token-exchange request. In "shadow" mode
	// it validates and audits the attempt but never issues a token; in "off" it
	// reports the grant as unsupported.
	ExchangeToken(ctx context.Context, form url.Values, clientID, clientSecret string) (*dto.TokenResponse, error)
	Introspect(ctx context.Context, token string) (*dto.IntrospectResponse, error)
	Revoke(ctx context.Context, token string, userID uint) error
	GetUserInfo(ctx context.Context, userID uint, clientID string) (*dto.UserInfoResponse, error)
	GetOpenIDConfiguration(issuer string) *dto.OpenIDConfiguration
	GetJWKS() dto.JWKS
	ValidatePasswordResetToken(ctx context.Context, token string) (email string, valid bool)
}

type oauthService struct {
	userRepo        repository.UserRepository
	appRepo         repository.AppRepository
	userAppRoleRepo repository.UserAppRoleRepository
	codeStore       *auth.CodeStore
	tokenService    *auth.TokenService
	keyManager      *auth.KeyManager
	auditRepo       repository.SecurityAuditLogRepository
	// usedTokenRepo tracks consumed refresh-token JTIs so that each refresh
	// token can only be used once (HIGH-04).  Nil disables the check (tests
	// that don't need JTI enforcement may leave it unset).
	usedTokenRepo repository.UsedTokenRepository
	issuer        string
	requireHTTPS  bool
	// tokenExchangeMode is "off" (default), "shadow", or "enforce" (RFC 8693 /
	// EPIC-16). Empty is treated as off.
	tokenExchangeMode string
	// impersonationTokenTTL time-boxes tokens minted via impersonation (the
	// actor-absent token-exchange case, EPIC-17), independently of the standard
	// access-token TTL. Impersonation is sensitive, so its tokens auto-expire
	// quickly. Zero falls back to the access-token TTL; the effective lifetime is
	// always capped at the access-token TTL (a time-box only ever shortens).
	impersonationTokenTTL time.Duration
	// impersonationStepUpMode is "off" (default), "observe", or "enforce"
	// (EPIC-17 step-up). When not off and impersonationMaxAuthAge > 0, an
	// impersonation exchange requires the subject to have authenticated within
	// that window; observe audits the would-be denial, enforce denies it.
	impersonationStepUpMode string
	// impersonationMaxAuthAge is the freshness window for impersonation step-up.
	// Zero disables the check.
	impersonationMaxAuthAge time.Duration
	// delegationStepUpMode is "off" (default), "observe", or "enforce" (EPIC-17
	// step-up). When not off, a delegation exchange requires the actor token to
	// evidence MFA (amr ⊇ {mfa}); observe audits the would-be denial, enforce
	// denies it.
	delegationStepUpMode string
	// refreshReuseMode is "off" (default), "observe", or "enforce" (RFC 9700
	// §4.14.2 refresh-token reuse detection). observe audits a detected reuse;
	// enforce additionally revokes the user's token family.
	refreshReuseMode string
}

// Token-exchange rollout modes (RFC 8693 / EPIC-16).
const (
	TokenExchangeModeOff     = "off"
	TokenExchangeModeShadow  = "shadow"
	TokenExchangeModeEnforce = "enforce"
)

// Impersonation step-up rollout modes (EPIC-17).
const (
	stepUpModeOff     = "off"
	stepUpModeObserve = "observe"
	stepUpModeEnforce = "enforce"
)

// Refresh-token reuse-detection modes (RFC 9700 §4.14.2). off = reject the
// reused token only (historical behaviour); observe = also audit the reuse;
// enforce = also revoke the user's token family.
const (
	refreshReuseModeOff     = "off"
	refreshReuseModeObserve = "observe"
	refreshReuseModeEnforce = "enforce"
)

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
	auditRepo repository.SecurityAuditLogRepository,
	usedTokenRepo repository.UsedTokenRepository,
	tokenExchangeMode string,
	impersonationTokenTTL time.Duration,
	impersonationStepUpMode string,
	impersonationMaxAuthAge time.Duration,
	delegationStepUpMode string,
	refreshReuseMode string,
) OAuthService {
	requireHTTPS := strings.HasPrefix(issuer, "https://")

	logger.WithFields(logger.Fields{
		"service":                    "oauth",
		"issuer":                     issuer,
		"require_https":              requireHTTPS,
		"token_exchange_mode":        tokenExchangeMode,
		"impersonation_token_ttl":    impersonationTokenTTL.String(),
		"impersonation_stepup_mode":  impersonationStepUpMode,
		"impersonation_max_auth_age": impersonationMaxAuthAge.String(),
		"delegation_stepup_mode":     delegationStepUpMode,
		"refresh_reuse_mode":         refreshReuseMode,
	}).Info("✅ OAuth service initialized")

	return &oauthService{
		userRepo:                userRepo,
		appRepo:                 appRepo,
		userAppRoleRepo:         userAppRoleRepo,
		codeStore:               codeStore,
		tokenService:            tokenService,
		keyManager:              keyManager,
		auditRepo:               auditRepo,
		usedTokenRepo:           usedTokenRepo,
		issuer:                  issuer,
		requireHTTPS:            requireHTTPS,
		tokenExchangeMode:       tokenExchangeMode,
		impersonationTokenTTL:   impersonationTokenTTL,
		impersonationStepUpMode: impersonationStepUpMode,
		impersonationMaxAuthAge: impersonationMaxAuthAge,
		delegationStepUpMode:    delegationStepUpMode,
		refreshReuseMode:        refreshReuseMode,
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
	auditRepo repository.SecurityAuditLogRepository,
	usedTokenRepo repository.UsedTokenRepository,
	config OAuthServiceConfig,
) OAuthService {
	logger.WithFields(logger.Fields{
		"service":       "oauth",
		"issuer":        issuer,
		"require_https": config.RequireHTTPS,
	}).Info("✅ OAuth service initialized")

	return &oauthService{
		userRepo:        userRepo,
		appRepo:         appRepo,
		userAppRoleRepo: userAppRoleRepo,
		codeStore:       codeStore,
		tokenService:    tokenService,
		keyManager:      keyManager,
		auditRepo:       auditRepo,
		usedTokenRepo:   usedTokenRepo,
		issuer:          issuer,
		requireHTTPS:    config.RequireHTTPS,
	}
}

// ErrReauthRequired is returned when the client's max_age constraint is not
// satisfied by the current session's auth_time.
var ErrReauthRequired = errors.New("re-authentication required")

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

	// LOW-02 fix: validate max_age (OIDC Core §3.1.2.1).
	//
	// max_age is the maximum elapsed time in seconds since the user last
	// authenticated.  When the client specifies it, the server MUST check
	// whether the current session satisfies the constraint.  If not the
	// user needs to re-authenticate before authorization proceeds.
	//
	// auth_time is tracked via user.LastLogin (most recent successful login
	// in the users table).  If LastLogin is nil the check is skipped — new
	// accounts without a recorded login time cannot satisfy the constraint.
	//
	// The nonce omission on refresh grants is intentional: auth_time is
	// propagated from the original refresh token (preserving the time of
	// the last actual user authentication) rather than being updated on each
	// refresh, which is correct OIDC behaviour.  See LOW-04.
	if req.MaxAge >= 0 && user.LastLogin != nil {
		sessionAge := int(time.Since(*user.LastLogin).Seconds())
		if sessionAge > req.MaxAge {
			return "", fmt.Errorf("%w: session age %ds exceeds max_age %ds",
				ErrReauthRequired, sessionAge, req.MaxAge)
		}
	}

	// MED-02: if this client requires PKCE (explicitly, or because it is a
	// public client — OAuth 2.1), reject authorization requests that arrive
	// without a code_challenge. This prevents public clients from accidentally
	// starting an unprotected authorization flow.
	if app.PKCERequired() && req.CodeChallenge == "" {
		return "", fmt.Errorf("%w: this client requires PKCE — include code_challenge in the authorization request", ErrPKCERequired)
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
		return s.handleRefreshTokenGrant(ctx, req, clientID, clientSecret)
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
		// RFC-007: a failed code redemption (invalid, expired, or already-used
		// code) is an attack signal (code replay / brute force) — audit it.
		s.logSecurityEvent(ctx, model.SecurityEventAuthCodeFailed, nil, nil, false, map[string]interface{}{
			"client_id": clientID,
			"reason":    "invalid_or_used_code",
		})
		return nil, ErrInvalidCode
	}

	// Verify client ID matches
	if authCode.ClientID != clientID {
		uid := authCode.UserID
		s.logSecurityEvent(ctx, model.SecurityEventAuthCodeFailed, &uid, nil, false, map[string]interface{}{
			"client_id": clientID,
			"reason":    "client_id_mismatch",
		})
		return nil, fmt.Errorf("%w: client_id mismatch", ErrInvalidCode)
	}

	// Verify redirect URI matches
	if authCode.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("%w: redirect_uri=%s", ErrInvalidRedirectURI, req.RedirectURI)
	}

	// MED-02 fix: enforce PKCE for clients that require it.
	//
	// The app lookup below is needed for both PKCE enforcement and the
	// CRIT-02 client-secret check, so we do it once here and reuse it.
	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, clientID)
	}

	// If the app requires PKCE (explicitly or as a public client), the
	// authorization request MUST have included a code_challenge. Reject token
	// requests that bypass PKCE entirely.
	if app.PKCERequired() && authCode.CodeChallenge == "" {
		return nil, fmt.Errorf("%w: PKCE required for this client but no code_challenge was supplied at authorization", ErrPKCERequired)
	}

	// Verify PKCE if used
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			uid := authCode.UserID
			s.logSecurityEvent(ctx, model.SecurityEventPKCEValidationFail, &uid, &app.ID, false, map[string]interface{}{
				"client_id": clientID,
				"reason":    "missing_code_verifier",
			})
			return nil, ErrPKCERequired
		}
		if err := auth.VerifyPKCE(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			// RFC-007: a PKCE verification failure is a strong signal of an
			// authorization-code interception attempt — audit it.
			uid := authCode.UserID
			s.logSecurityEvent(ctx, model.SecurityEventPKCEValidationFail, &uid, &app.ID, false, map[string]interface{}{
				"client_id": clientID,
				"reason":    "verification_failed",
			})
			return nil, fmt.Errorf("%w: %v", ErrPKCEVerificationFail, err)
		}
	}

	// CRIT-02 fix: enforce client authentication for confidential clients.
	// (app was already fetched above for MED-02 PKCE enforcement — reused here)
	//
	// A client is considered confidential when it has a stored secret hash.
	// Confidential clients MUST supply their secret at the token endpoint
	// (RFC 6749 §3.2.1).  Public clients (mobile apps, SPAs) have an empty
	// ClientSecretHash and authenticate via PKCE instead.
	//
	// The previous check was conditioned on `clientSecret != ""`, which
	// allowed confidential clients to exchange codes without authenticating
	// by simply omitting the secret.  We now require it whenever the app
	// has a stored hash.
	if app.ClientSecretHash != "" {
		if clientSecret == "" {
			s.logClientAuthFailed(ctx, clientID, "missing_secret", &app.ID)
			return nil, fmt.Errorf("%w: client_secret required for confidential client", ErrInvalidCredentials)
		}
		if !auth.CheckClientSecret(clientSecret, app.ClientSecretHash) {
			s.logClientAuthFailed(ctx, clientID, "invalid_secret", &app.ID)
			return nil, ErrInvalidCredentials
		}
	}

	// RFC 9449 / EPIC-8: enforce the per-client DPoP requirement.
	if err := requireDPoP(ctx, app); err != nil {
		return nil, err
	}

	// Get the user
	user, err := s.userRepo.FindByID(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: user_id=%d", ErrUserNotFound, authCode.UserID)
	}

	// Generate tokens
	now := time.Now()
	tokenSet, err := s.tokenService.GenerateTokenSetWithDPoP(
		user,
		app,
		authCode.Role,
		authCode.Scope,
		authCode.AppRoles,
		authCode.Nonce,
		now.Unix(),
		dpopJKTFromContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token set: %w", err)
	}

	roles := []string{}
	if authCode.Role != "" {
		roles = append(roles, authCode.Role)
	}

	// Log token issuance with token types
	tokenTypes := []string{"access_token", "refresh_token"}
	if tokenSet.IDToken != "" {
		tokenTypes = append(tokenTypes, "id_token")
	}
	s.logSecurityEvent(ctx, model.SecurityEventTokenIssued, &user.ID, &app.ID, true, map[string]interface{}{
		"grant_type":  "authorization_code",
		"scope":       authCode.Scope,
		"client_id":   clientID,
		"token_types": tokenTypes,
	})

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

func (s *oauthService) handleRefreshTokenGrant(ctx context.Context, req dto.TokenRequest, clientID, clientSecret string) (*dto.TokenResponse, error) {
	claims, err := s.tokenService.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Verify client ID matches the token's audience.
	// HIGH-03 / MED-06 fix: require a non-empty audience AND verify it matches
	// the requesting client.  A token whose audience is empty must be rejected
	// outright: the conditional `len > 0` guard in the original code allowed
	// any clientID to claim a token with no audience, completely bypassing the
	// binding between a refresh token and its issuing client.
	if len(claims.Audience) == 0 || claims.Audience[0] != clientID {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}

	// RFC 9449 §5: a sender-constrained refresh token must be presented with a
	// DPoP proof for the same key.
	cnfJKT := ""
	if claims.Cnf != nil {
		cnfJKT = claims.Cnf.JKT
	}
	if err := verifyRefreshDPoPBinding(ctx, cnfJKT); err != nil {
		return nil, err
	}

	// HIGH-04 fix: enforce single-use on refresh tokens by checking whether
	// the token's JTI has already been consumed.  This closes the replay
	// window that exists when both the attacker and the legitimate user hold
	// the same stateless JWT refresh token simultaneously.
	//
	// The check is best-effort: if usedTokenRepo is nil (e.g. in tests that
	// don't exercise this path) the guard is skipped rather than panicking.
	jti := claims.ID
	if s.usedTokenRepo != nil && jti != "" {
		used, err := s.usedTokenRepo.IsUsed(ctx, jti)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to verify token single-use", ErrInvalidToken)
		}
		if used {
			// RFC 9700 §4.14.2: presenting an already-rotated refresh token is a
			// token-theft signal. Beyond rejecting this request, optionally revoke
			// the user's whole token family so neither the attacker's nor the
			// victim's outstanding tokens survive. observe records the event;
			// enforce additionally revokes. off keeps the historical behaviour
			// (reject only). The token's signature + audience were already verified
			// above, so the subject is trustworthy provenance for the revocation.
			if s.refreshReuseMode != refreshReuseModeOff {
				uid64, _ := strconv.ParseUint(claims.Subject, 10, 64)
				uid := uint(uid64)
				reuseDetails := map[string]interface{}{
					"jti":       jti,
					"client_id": clientID,
					"mode":      s.refreshReuseMode,
				}
				if s.refreshReuseMode == refreshReuseModeEnforce {
					if rerr := s.userRepo.IncrementTokenVersion(ctx, uid); rerr != nil {
						logger.Errorf("RFC 9700: failed to revoke token family on refresh reuse for user %d: %v", uid, rerr)
					} else {
						reuseDetails["family_revoked"] = true
					}
				}
				s.logSecurityEvent(ctx, model.SecurityEventRefreshTokenReuse, &uid, nil, false, reuseDetails)
			}
			return nil, fmt.Errorf("%w: refresh token has already been used", ErrInvalidToken)
		}
	}

	// HIGH-03 fix: authenticate the client BEFORE looking up user data.
	// Moving the app lookup and credential check here (ahead of the user
	// lookup) ensures that an unauthenticated confidential-client request
	// is rejected with ErrInvalidCredentials rather than leaking whether
	// the user exists (ErrUserNotFound).
	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, clientID)
	}

	if app.ClientSecretHash != "" {
		if clientSecret == "" {
			s.logClientAuthFailed(ctx, clientID, "missing_secret", &app.ID)
			return nil, fmt.Errorf("%w: client_secret required for confidential client", ErrInvalidCredentials)
		}
		if !auth.CheckClientSecret(clientSecret, app.ClientSecretHash) {
			s.logClientAuthFailed(ctx, clientID, "invalid_secret", &app.ID)
			return nil, ErrInvalidCredentials
		}
	}

	// RFC 9449 / EPIC-8: enforce the per-client DPoP requirement.
	if err := requireDPoP(ctx, app); err != nil {
		return nil, err
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

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: user has no role for app", ErrRoleNotFound)
	}

	appRoles, _ := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if appRoles == nil {
		appRoles = make(map[string]string)
	}

	// LOW-04 / LOW-02 note: nonce is intentionally omitted (passed as "")
	// when issuing tokens via the refresh grant.
	//
	// OIDC Core §12 specifies that the nonce MUST NOT be included in ID
	// tokens issued via the refresh grant because the nonce binds the ID
	// token to a specific authentication request — re-using it on a
	// subsequently issued token would break replay-detection logic in
	// well-behaved clients.
	//
	// auth_time (claims.AuthTime) is propagated from the original refresh
	// token rather than being updated to time.Now().  This preserves the
	// time of the last actual user authentication, which is the correct
	// semantic: refreshing does not constitute a new authentication event.
	// Resource servers relying on auth_time for session-freshness enforcement
	// should use max_age on the authorization request to force re-auth when
	// needed (see LOW-02 / ErrReauthRequired).
	tokenSet, err := s.tokenService.GenerateTokenSetWithDPoP(
		user,
		app,
		string(userAppRole.Role),
		claims.Scope,
		appRoles,
		"", // nonce: intentionally absent on refresh — see LOW-04 comment above
		claims.AuthTime,
		dpopJKTFromContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token set: %w", err)
	}

	// HIGH-04 fix: mark the consumed refresh token JTI as used so future
	// attempts to replay the same token are rejected.  We do this after
	// generating the new token set so that a generation failure does not
	// poison the JTI and lock the user out.
	if s.usedTokenRepo != nil && jti != "" {
		exp := claims.ExpiresAt.Time
		if markErr := s.usedTokenRepo.MarkAsUsed(ctx, jti, "refresh", user.ID, exp); markErr != nil {
			// ErrTokenAlreadyUsed indicates a concurrent replay — reject.
			if errors.Is(markErr, repository.ErrTokenAlreadyUsed) {
				return nil, fmt.Errorf("%w: concurrent refresh token replay detected", ErrInvalidToken)
			}
			// Any other DB error is non-fatal: log it but don't break the
			// user's session; the IsUsed pre-check provides the main guard.
			logger.Errorf("HIGH-04: failed to mark refresh token JTI as used: %v", markErr)
		}
	}

	roles := []string{string(userAppRole.Role)}

	// Log token refresh with token types
	refreshTokenTypes := []string{"access_token", "refresh_token"}
	if tokenSet.IDToken != "" {
		refreshTokenTypes = append(refreshTokenTypes, "id_token")
	}
	s.logSecurityEvent(ctx, model.SecurityEventTokenRefreshed, &user.ID, &app.ID, true, map[string]interface{}{
		"grant_type":  "refresh_token",
		"scope":       claims.Scope,
		"client_id":   clientID,
		"token_types": refreshTokenTypes,
	})

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
		s.logClientAuthFailed(ctx, clientID, "missing_secret", nil)
		return nil, fmt.Errorf("%w: client_secret required for client_credentials grant", ErrInvalidCredentials)
	}

	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, clientID)
	}

	if !auth.CheckClientSecret(clientSecret, app.ClientSecretHash) {
		s.logClientAuthFailed(ctx, clientID, "invalid_secret", &app.ID)
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

	// Log token issuance (no user for client_credentials grant, only access_token)
	s.logSecurityEvent(ctx, model.SecurityEventTokenIssued, nil, &app.ID, true, map[string]interface{}{
		"grant_type":  "client_credentials",
		"scope":       scope,
		"client_id":   clientID,
		"token_types": []string{"access_token"},
	})

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

	// MED-01 fix: check whether this token's JTI has been explicitly revoked.
	// A token that passed signature and expiry checks but was subsequently
	// blacklisted via /oauth/revoke must return active:false.
	if s.usedTokenRepo != nil && claims.ID != "" {
		if revoked, rErr := s.usedTokenRepo.IsUsed(ctx, claims.ID); rErr == nil && revoked {
			return &dto.IntrospectResponse{Active: false}, nil
		}
	}

	userID, _ := strconv.ParseUint(claims.Subject, 10, 64)
	user, err := s.userRepo.FindByID(ctx, uint(userID))

	// NEW-03 fix: check token version against the user's current TokenVersion.
	// Nuclear revocation (IncrementTokenVersion via EndSession or admin API)
	// bumps the user's stored version.  Any access token whose embedded
	// TokenVersion is lower than the current value must be treated as revoked,
	// even if its JTI has not been explicitly blacklisted.
	//
	// This aligns Introspect with the auth middleware (internal/middleware/auth.go),
	// which already performs this check for direct API calls.  Without it,
	// resource servers relying on introspection would not see nuclear revocations
	// until the token expires naturally.
	if err == nil && user.TokenVersion > claims.TokenVersion {
		return &dto.IntrospectResponse{Active: false}, nil
	}

	username := ""
	if err == nil {
		username = user.Email
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}

	resp := &dto.IntrospectResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  clientID,
		Username:  username,
		TokenType: "Bearer",
		Exp:       claims.ExpiresAt.Unix(),
		Iat:       claims.IssuedAt.Unix(),
		Sub:       claims.Subject,
		Aud:       []string(claims.Audience),
		AuthTime:  claims.AuthTime,
		Amr:       claims.Amr,
		Acr:       claims.Acr,
	}
	// Surface DPoP sender-constraint so resource servers can enforce it
	// (RFC 7662 §2.2 / RFC 9449 §7).
	if claims.Cnf != nil && claims.Cnf.JKT != "" {
		resp.Cnf = &dto.CnfClaim{JKT: claims.Cnf.JKT}
	}
	// Surface the actor chain for delegated/impersonated tokens (RFC 8693 §4.1).
	resp.Act = mapActClaim(claims.Act)
	return resp, nil
}

// amrContains reports whether the authentication-methods list includes method.
func amrContains(amr []string, method string) bool {
	for _, m := range amr {
		if m == method {
			return true
		}
	}
	return false
}

// mapActClaim converts the auth actor claim to its introspection DTO,
// preserving the (possibly nested) delegation chain. Returns nil for nil input.
func mapActClaim(a *auth.ActClaim) *dto.ActClaim {
	if a == nil {
		return nil
	}
	return &dto.ActClaim{Sub: a.Sub, Act: mapActClaim(a.Act)}
}

// Revoke handles token revocation (RFC 7009).
//
// MED-01 fix: implement per-token revocation by blacklisting the specific
// token's JTI in the used_tokens table (reusing the existing infrastructure
// from the HIGH-04 single-use refresh token enforcement).
//
// RFC 7009 §2 states that revocation MUST apply to the specific token
// presented.  The previous implementation incremented the user's token
// version, which silently logged out every device and session — a "nuclear"
// option that violated the RFC and surprised users.
//
// Behaviour:
//   - If the token parses successfully, block its JTI and return.  This is a
//     targeted, RFC-compliant revocation.
//   - If the token is malformed or already expired we cannot extract its JTI,
//     so we fall back to the nuclear IncrementTokenVersion as a best-effort
//     safety net (only when a userID is supplied).
//   - Introspect() now checks whether the JTI is blacklisted, so a revoked
//     token immediately shows `active: false`.
func (s *oauthService) Revoke(ctx context.Context, token string, userID uint) error {
	// Attempt per-token revocation via JTI blacklist.
	if token != "" && s.usedTokenRepo != nil {
		claims, err := s.tokenService.VerifyAccessToken(token)
		if err == nil && claims.ID != "" {
			// Token is valid and carries a JTI — blacklist it.
			exp := claims.ExpiresAt.Time
			if markErr := s.usedTokenRepo.MarkAsUsed(ctx, claims.ID, "revoked", userID, exp); markErr != nil &&
				!errors.Is(markErr, repository.ErrTokenAlreadyUsed) {
				// A real DB error — log and continue; still return success to
				// caller per RFC 7009 (revocation always returns 200).
				logger.Errorf("MED-01: failed to blacklist token JTI %s: %v", claims.ID, markErr)
			}
			s.logSecurityEvent(ctx, model.SecurityEventTokenRevoked, &userID, nil, true, map[string]interface{}{
				"action": "revoke_token",
				"jti":    claims.ID,
			})
			return nil
		}
		// Try refresh token if access token parse failed.
		rClaims, rErr := s.tokenService.VerifyRefreshToken(token)
		if rErr == nil && rClaims.ID != "" {
			exp := rClaims.ExpiresAt.Time
			if markErr := s.usedTokenRepo.MarkAsUsed(ctx, rClaims.ID, "revoked", userID, exp); markErr != nil &&
				!errors.Is(markErr, repository.ErrTokenAlreadyUsed) {
				logger.Errorf("MED-01: failed to blacklist refresh token JTI %s: %v", rClaims.ID, markErr)
			}
			s.logSecurityEvent(ctx, model.SecurityEventTokenRevoked, &userID, nil, true, map[string]interface{}{
				"action": "revoke_refresh_token",
				"jti":    rClaims.ID,
			})
			return nil
		}
	}

	// Fallback: token is absent or malformed — use nuclear revocation to
	// ensure the user's session is invalidated (e.g. EndSession without a
	// token hint, or a token that cannot be parsed).
	if userID != 0 {
		if err := s.userRepo.IncrementTokenVersion(ctx, userID); err != nil {
			return fmt.Errorf("failed to revoke tokens: %w", err)
		}
		s.logSecurityEvent(ctx, model.SecurityEventTokenRevokedAll, &userID, nil, true, map[string]interface{}{
			"action": "revoke_all_tokens_fallback",
		})
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
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth/authorize",
		TokenEndpoint:         issuer + "/oauth/token",
		UserinfoEndpoint:      issuer + "/oauth/userinfo",
		JwksURI:               issuer + "/.well-known/jwks.json",
		IntrospectionEndpoint: issuer + "/oauth/introspect",
		RevocationEndpoint:    issuer + "/oauth/revoke",
		// H-01 fix: only "code" is advertised — implicit and hybrid flows are removed.
		ResponseTypesSupported: []string{"code"},
		// H-02 fix: only "S256" is advertised — "plain" provides no security benefit
		// (the code_verifier IS the code_challenge, so interception defeats it).
		CodeChallengeMethodsSupported:    []string{"S256"},
		GrantTypesSupported:              []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "email", "profile", "offline_access", "api"},
		// HIGH-08 fix: remove "none" from token_endpoint_auth_methods_supported.
		// Advertising "none" signals that unauthenticated token requests are
		// acceptable, which misleads clients and relying parties.  Public clients
		// using PKCE do not need "none" in this list — they simply omit credentials.
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		// Claims the OP may assert. Beyond the core OIDC set this advertises the
		// claims added by recent capabilities: auth_time (RFC 9068), acr/amr
		// (RFC 8176), act (RFC 8693 delegation), and cnf (RFC 9449 DPoP). A claim
		// being listed does not mean it is present on every token.
		ClaimsSupported:    []string{"sub", "iss", "aud", "exp", "iat", "nbf", "email", "email_verified", "name", "preferred_username", "role", "app_roles", "token_version", "auth_time", "acr", "amr", "act", "cnf"},
		AcrValuesSupported: []string{"pwd", "mfa"},
		// RFC 9207: the authorization response includes the `iss` parameter.
		AuthorizationResponseIssParameterSupported: true,
	}
}

// GetJWKS returns the JSON Web Key Set
func (s *oauthService) GetJWKS() dto.JWKS {
	return s.keyManager.GetJWKS()
}

// ValidatePasswordResetToken validates a password reset token and returns the email if valid
func (s *oauthService) ValidatePasswordResetToken(ctx context.Context, token string) (string, bool) {
	claims, err := s.tokenService.VerifyEmailToken(token)
	if err != nil {
		return "", false
	}

	if claims.Type != "password_reset" || claims.Action != "reset" {
		return "", false
	}

	return claims.Email, true
}

// isValidResponseType enforces the OAuth 2.1 / RFC 9700 mandate that only the
// Authorization Code flow is supported.
//
// H-01 fix: "token" (implicit grant) and hybrid flows ("id_token",
// "code id_token") are removed.  The implicit grant puts access tokens in URL
// fragments, exposing them via Referer headers, browser history, and server
// logs.  OAuth 2.1 formally deprecates it; we follow suit.
func isValidResponseType(responseType string) bool {
	return responseType == "code"
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

// ExchangeToken implements the RFC 8693 token-exchange grant in "shadow" mode:
// it verifies the presented subject (and actor) tokens, evaluates the
// authorization policy, and audits the would-be decision — but never issues a
// token (the grant is reported unsupported). "off" reports the grant unsupported
// without auditing. Actual issuance is the enforce slice.
func (s *oauthService) ExchangeToken(ctx context.Context, form url.Values, clientID, clientSecret string) (*dto.TokenResponse, error) {
	if s.tokenExchangeMode != TokenExchangeModeShadow && s.tokenExchangeMode != TokenExchangeModeEnforce {
		return nil, ErrInvalidGrantType
	}
	enforce := s.tokenExchangeMode == TokenExchangeModeEnforce

	// Resolve the requesting client for the policy + telemetry.
	var app *model.App
	var appID *uint
	allowTE, allowImp := false, false
	if a, aerr := s.appRepo.FindByClientID(ctx, clientID); aerr == nil {
		app, appID = a, &a.ID
		allowTE, allowImp = a.AllowTokenExchange, a.AllowImpersonation
	}

	details := map[string]interface{}{
		"client_id":            clientID,
		"mode":                 s.tokenExchangeMode,
		"allow_token_exchange": allowTE,
		"allow_impersonation":  allowImp,
	}
	// Audit the decision exactly once, on every return path.
	defer func() {
		s.logSecurityEvent(ctx, model.SecurityEventTokenExchange, nil, appID, false, details)
	}()

	// fail records the outcome and returns the right error per mode: in shadow
	// every failure is invisible (unsupported_grant_type); in enforce the
	// specific RFC 8693 error is surfaced.
	fail := func(outcome string, enforceErr error) (*dto.TokenResponse, error) {
		details["outcome"] = outcome
		if enforce {
			return nil, enforceErr
		}
		return nil, ErrInvalidGrantType
	}

	req, perr := tokenexchange.Parse(form)
	if perr != nil {
		details["error"] = perr.Error()
		return fail("parse_error", ErrInvalidExchangeRequest)
	}
	details["is_delegation"] = req.IsDelegation()
	details["subject_token_type"] = req.SubjectTokenType
	details["requested_token_type"] = req.RequestedTokenType

	// Verify the subject token and recover its subject, scope, version, and the
	// end-user's authentication time (for the impersonation step-up check).
	subjectSub, subjectScope, subjectVer, subjectAuthTime, _, sverr := s.verifyExchangeToken(req.SubjectToken, req.SubjectTokenType)
	if sverr != nil {
		return fail("invalid_subject_token", ErrInvalidToken)
	}
	details["subject_sub"] = subjectSub

	// For delegation, verify the actor token too and recover its authentication
	// methods (amr) for the delegation step-up check.
	actorSub := ""
	var actorAmr []string
	if req.IsDelegation() {
		as, _, _, _, aamr, averr := s.verifyExchangeToken(req.ActorToken, req.ActorTokenType)
		if averr != nil {
			return fail("invalid_actor_token", ErrInvalidToken)
		}
		actorSub, actorAmr = as, aamr
		details["actor_sub"] = actorSub
	}

	// Authenticate the requesting client (default-deny): an unknown client, or a
	// confidential client with a bad secret, may not exchange.
	if app == nil {
		details["deny_reason"] = "unknown_client"
		return fail("denied", ErrInvalidCredentials)
	}
	if app.ClientSecretHash != "" && !auth.CheckClientSecret(clientSecret, app.ClientSecretHash) {
		details["deny_reason"] = "invalid_client"
		return fail("denied", ErrInvalidCredentials)
	}

	// Authorization policy (default-deny, downscope-only, audience-bound).
	decision, derr := authorizeExchange(app, req, subjectScope)
	if derr != nil {
		details["deny_reason"] = derr.Error()
		return fail("denied", derr)
	}
	details["granted_scope"] = decision.GrantedScope
	if len(decision.Audience) > 0 {
		details["audience"] = decision.Audience
	}

	if !enforce {
		details["outcome"] = "shadow_allow"
		return nil, ErrInvalidGrantType
	}

	// Impersonation step-up (EPIC-17): the subject (the user being impersonated)
	// must have authenticated recently. There is no interactive user at this
	// back-channel exchange, so freshness of the subject's session (auth_time,
	// OIDC max_age semantics) is the control that bounds an impersonation grant's
	// reach. A missing auth_time can't prove freshness and is treated as stale.
	// observe audits the would-be denial but still issues; enforce denies.
	if decision.IsImpersonation && s.impersonationStepUpMode != stepUpModeOff && s.impersonationMaxAuthAge > 0 {
		details["stepup_mode"] = s.impersonationStepUpMode
		fresh := subjectAuthTime > 0 && time.Since(time.Unix(subjectAuthTime, 0)) <= s.impersonationMaxAuthAge
		if subjectAuthTime > 0 {
			details["subject_auth_age_seconds"] = int(time.Since(time.Unix(subjectAuthTime, 0)).Seconds())
		}
		if !fresh {
			switch s.impersonationStepUpMode {
			case stepUpModeEnforce:
				details["deny_reason"] = ErrStepUpRequired.Error()
				return fail("denied", ErrStepUpRequired)
			case stepUpModeObserve:
				details["stepup"] = "would_deny" // record but still issue
			}
		} else {
			details["stepup"] = "fresh"
		}
	}

	// Delegation step-up (EPIC-17 / RFC-016): the human actor doing the
	// delegating must have authenticated with MFA. Unlike impersonation (no human
	// at the exchange), delegation carries an actor token whose `amr` evidences
	// how that human logged in, so requiring `mfa` there is the step-up control.
	// An actor token without `amr` (or without `mfa`) cannot prove it. observe
	// audits the would-be denial but still issues; enforce denies.
	if !decision.IsImpersonation && s.delegationStepUpMode != stepUpModeOff {
		details["delegation_stepup_mode"] = s.delegationStepUpMode
		if !amrContains(actorAmr, "mfa") {
			switch s.delegationStepUpMode {
			case stepUpModeEnforce:
				details["deny_reason"] = ErrDelegationStepUpRequired.Error()
				return fail("denied", ErrDelegationStepUpRequired)
			case stepUpModeObserve:
				details["delegation_stepup"] = "would_deny"
			}
		} else {
			details["delegation_stepup"] = "mfa"
		}
	}

	// Enforce: mint the exchanged token. The act (actor) claim records who is
	// acting — the actor token's subject for delegation, the requesting client
	// for impersonation — so both principals stay visible downstream.
	actor := &auth.ActClaim{Sub: actorSub}
	if !req.IsDelegation() {
		actor = &auth.ActClaim{Sub: "client:" + clientID}
	}
	// Time-box impersonation (EPIC-17): an impersonated token auto-expires on a
	// short, bounded lifetime — never longer than a normal access token — so a
	// leaked impersonation token is usable only briefly. Delegation keeps the
	// standard access-token TTL.
	ttl := s.impersonationExchangeTTL(decision.IsImpersonation)
	if decision.IsImpersonation {
		details["impersonation"] = true
		details["token_ttl_seconds"] = int(ttl.Seconds())
	}
	// Sender-constrain the exchanged token to the client's DPoP key when the
	// exchange request carried a valid proof (verified by the token-endpoint
	// middleware and stashed on the context). Opportunistic — RFC 9449.
	jkt := dpopJKTFromContext(ctx)
	token, expiresIn, merr := s.tokenService.GenerateExchangedTokenWithTTL(subjectSub, decision.Audience, decision.GrantedScope, subjectVer, actor, jkt, ttl)
	if merr != nil {
		return fail("error", fmt.Errorf("failed to issue exchanged token: %w", merr))
	}
	details["outcome"] = "issued"
	details["dpop_bound"] = jkt != ""
	return &dto.TokenResponse{
		AccessToken:     token,
		TokenType:       "Bearer",
		ExpiresIn:       expiresIn,
		Scope:           decision.GrantedScope,
		IssuedTokenType: tokenexchange.TokenTypeAccessToken,
	}, nil
}

// impersonationExchangeTTL returns the lifetime for an exchanged token. For
// delegation it returns 0 (the issuance primitive then uses the standard
// access-token TTL). For impersonation it returns the configured time-box,
// capped at the access-token TTL so an impersonated token is never longer-lived
// than a normal one. A zero/unset impersonation TTL also falls back to the
// access-token TTL (no time-box configured). EPIC-17.
func (s *oauthService) impersonationExchangeTTL(isImpersonation bool) time.Duration {
	if !isImpersonation || s.impersonationTokenTTL <= 0 {
		return 0
	}
	if access := s.tokenService.GetAccessTokenTTL(); access > 0 && s.impersonationTokenTTL > access {
		return access
	}
	return s.impersonationTokenTTL
}

// verifyExchangeToken verifies a token presented to the exchange and returns its
// subject, scope, token version, the end-user authentication time (auth_time, 0
// when the token carries none), and the authentication methods (amr, nil when
// the token carries none), dispatching on the RFC 8693 token type.
func (s *oauthService) verifyExchangeToken(tokenStr, tokenType string) (sub, scope string, version int, authTime int64, amr []string, err error) {
	switch tokenType {
	case tokenexchange.TokenTypeAccessToken, tokenexchange.TokenTypeJWT:
		c, e := s.tokenService.VerifyAccessToken(tokenStr)
		if e != nil {
			return "", "", 0, 0, nil, e
		}
		return c.Subject, c.Scope, c.TokenVersion, c.AuthTime, c.Amr, nil
	case tokenexchange.TokenTypeRefreshToken:
		c, e := s.tokenService.VerifyRefreshToken(tokenStr)
		if e != nil {
			return "", "", 0, 0, nil, e
		}
		return c.Subject, c.Scope, c.Ver, c.AuthTime, nil, nil
	case tokenexchange.TokenTypeIDToken:
		c, e := s.tokenService.VerifyIDToken(tokenStr)
		if e != nil {
			return "", "", 0, 0, nil, e
		}
		return c.Subject, "", 0, c.AuthTime, c.Amr, nil
	default:
		return "", "", 0, 0, nil, fmt.Errorf("unsupported token type %q", tokenType)
	}
}

// logClientAuthFailed audits a confidential-client authentication failure at the
// token endpoint (RFC-007). appID may be nil when the client could not be
// resolved. reason is "missing_secret" or "invalid_secret".
func (s *oauthService) logClientAuthFailed(ctx context.Context, clientID, reason string, appID *uint) {
	s.logSecurityEvent(ctx, model.SecurityEventClientAuthFailed, nil, appID, false, map[string]interface{}{
		"client_id": clientID,
		"reason":    reason,
	})
}

// logSecurityEvent logs a security event to the audit log.
func (s *oauthService) logSecurityEvent(ctx context.Context, eventType model.SecurityEventType, userID *uint, appID *uint, success bool, details map[string]interface{}) {
	if s.auditRepo == nil {
		return
	}

	// RFC-008: build via the shared helper so the correlation ID from the
	// request context is stamped on oauth/token audit rows.
	log := newSecurityAuditLog(ctx, eventType, userID, appID, "", "", success, details)

	// Fire and forget - don't let audit logging failure affect the main operation
	_ = s.auditRepo.Create(ctx, log)
}
