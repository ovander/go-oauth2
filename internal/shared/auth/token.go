package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ovander/go-oauth2/internal/model"
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

// Audience-binding rollout modes (RFC-001 / EPIC-7) controlling how an access
// token's `aud` is built from the client and its registered audiences.
const (
	// AudienceModeOff: aud = client_id (the historical behaviour).
	AudienceModeOff = "off"
	// AudienceModeDual: aud = client_id + the client's registered audiences.
	// Additive — resource servers still verifying client_id keep passing, while
	// audience-aware ones can begin checking their resource identifier. This is
	// the safe warn/observe step before canonical-only enforcement (Wave 2).
	AudienceModeDual = "dual"
)

// TokenService handles JWT token generation and verification
type TokenService struct {
	keyManager      *KeyManager
	signer          Signer
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	emailTokenTTL   time.Duration
	resetTokenTTL   time.Duration
	inviteTokenTTL  time.Duration
	audienceMode    string
	// claimsEnricher supplies the per-client custom claims (A2). Nil (the
	// default) means tokens carry exactly the standard claim set.
	claimsEnricher ClaimsEnricher
}

// SetClaimsEnricher installs the custom-claims enricher (A2). It is set once at
// bootstrap, before the service handles traffic; passing nil disables custom
// claims. It is a setter rather than a constructor argument so every existing
// call site — including the tests — keeps working unchanged.
func (ts *TokenService) SetClaimsEnricher(e ClaimsEnricher) {
	ts.claimsEnricher = e
}

// customClaims resolves the client's mapped claims for one token target,
// tolerating a nil enricher.
func (ts *TokenService) customClaims(user *model.User, app *model.App, role, target string) map[string]any {
	if ts.claimsEnricher == nil {
		return nil
	}
	return ts.claimsEnricher.CustomClaims(user, app, role, target)
}

// TokenConfig holds token configuration
type TokenConfig struct {
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	EmailTokenTTL   time.Duration
	ResetTokenTTL   time.Duration
	InviteTokenTTL  time.Duration
	// AudienceMode is "off" (default) or "dual" (RFC-001 / EPIC-7). Empty is off.
	AudienceMode string
}

// NewTokenService creates a new token service backed by the default local
// signer (in-process RSA key from the KeyManager). Behaviour is identical to
// signing directly with the KeyManager.
func NewTokenService(keyManager *KeyManager, config TokenConfig) *TokenService {
	return NewTokenServiceWithSigner(keyManager, NewLocalSigner(keyManager), config)
}

// NewTokenServiceWithSigner creates a token service that signs tokens with the
// supplied Signer. This is the injection point for RFC-002 (KMS Signing): a
// future KMS/HSM-backed Signer can be provided here without changing any
// call site. The keyManager is still used for public-key verification and the
// JWKS endpoint. If signer is nil, the default local signer is used.
func NewTokenServiceWithSigner(keyManager *KeyManager, signer Signer, config TokenConfig) *TokenService {
	if signer == nil {
		signer = NewLocalSigner(keyManager)
	}
	return &TokenService{
		keyManager:      keyManager,
		signer:          signer,
		issuer:          config.Issuer,
		accessTokenTTL:  config.AccessTokenTTL,
		refreshTokenTTL: config.RefreshTokenTTL,
		emailTokenTTL:   config.EmailTokenTTL,
		resetTokenTTL:   config.ResetTokenTTL,
		inviteTokenTTL:  config.InviteTokenTTL,
		audienceMode:    config.AudienceMode,
	}
}

// accessAudience builds the access token's `aud` per the audience-binding mode
// (RFC-001 / EPIC-7). In "dual" mode the client's registered audiences are
// appended to the client_id (deduplicated, order-stable). In "off" mode — or
// when the client has no registered audiences — it is just the client_id, so
// behaviour is unchanged.
func (ts *TokenService) accessAudience(app *model.App) []string {
	aud := []string{app.ClientID}
	if ts.audienceMode != AudienceModeDual || len(app.Audiences) == 0 {
		return aud
	}
	seen := map[string]bool{app.ClientID: true}
	for _, a := range app.Audiences {
		if a != "" && !seen[a] {
			seen[a] = true
			aud = append(aud, a)
		}
	}
	return aud
}

// GetIssuer returns the configured issuer URL
func (s *TokenService) GetIssuer() string {
	return s.issuer
}

// GetAudienceMode returns the configured audience-binding mode ("off"/"dual",
// RFC-001 / EPIC-7).
func (s *TokenService) GetAudienceMode() string {
	if s.audienceMode == "" {
		return AudienceModeOff
	}
	return s.audienceMode
}

// Confirmation is the RFC 7800 `cnf` (confirmation) claim. For DPoP (RFC 9449)
// it carries `jkt` — the base64url SHA-256 thumbprint of the JWK the access
// token is bound to, so a resource server can require a matching DPoP proof.
type Confirmation struct {
	JKT string `json:"jkt,omitempty"`
}

// ActClaim is the RFC 8693 §4.1 `act` (actor) claim. It records the party
// currently acting on the subject's behalf in a delegation, and nests to
// represent a chain of delegation (the outermost `act` is the most recent
// actor). Carrying it keeps both principals visible to downstream services.
type ActClaim struct {
	Sub string    `json:"sub"`
	Act *ActClaim `json:"act,omitempty"`
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
	// AuthTime is the time of the end-user's last authentication, as seconds
	// since the epoch (RFC 9068 §2.2.1 / OIDC auth_time). It lets a resource
	// server make its own freshness/step-up decisions without a round-trip to
	// the ID token. Zero/omitted on tokens with no associated user
	// authentication (e.g. client-credentials or token-exchange results).
	AuthTime int64 `json:"auth_time,omitempty"`
	// Amr / Acr are the OIDC / RFC 8176 authentication-methods-references and
	// authentication-context-class-reference (also part of the RFC-001 canonical
	// claim set / RFC 9068 access-token claims). Present when the issuing flow
	// knows how the user authenticated (e.g. interactive login: `pwd`, plus
	// `otp`/`mfa` when a second factor was used); omitted otherwise.
	Amr []string `json:"amr,omitempty"`
	Acr string   `json:"acr,omitempty"`
	// Cnf is the optional DPoP/RFC 7800 confirmation claim (sender-constraint).
	// Absent (nil) for ordinary bearer tokens.
	Cnf *Confirmation `json:"cnf,omitempty"`
	// Act is the optional RFC 8693 actor claim, present only on tokens minted via
	// token exchange (delegation). Absent (nil) for ordinary tokens.
	Act *ActClaim `json:"act,omitempty"`
	// Custom holds the client's mapped custom claims (A2), already namespaced.
	// It is merged into the token at the top level by MarshalJSON — never
	// overwriting a claim above — and is not itself a claim, hence json:"-".
	Custom map[string]any `json:"-"`
}

// MarshalJSON serializes the claims with the custom (mapped) claims merged in
// at the top level. A custom claim can never replace a registered or standard
// claim: a name that is already present is skipped.
func (c AccessTokenClaims) MarshalJSON() ([]byte, error) {
	type alias AccessTokenClaims
	return marshalWithCustomClaims(alias(c), c.Custom)
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
	// Cnf is the optional DPoP/RFC 7800 confirmation claim. When set, the refresh
	// token is sender-constrained: a refresh request must present a DPoP proof
	// for the same key (RFC 9449 §5). Absent for ordinary bearer refresh tokens.
	Cnf *Confirmation `json:"cnf,omitempty"`
}

// IDTokenClaims represents ID token claims (OpenID Connect)
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email             string            `json:"email,omitempty"`
	EmailVerified     bool              `json:"email_verified,omitempty"`
	Name              string            `json:"name,omitempty"`
	PreferredUsername string            `json:"preferred_username,omitempty"`
	AuthTime          int64             `json:"auth_time,omitempty"`
	Role              string            `json:"role,omitempty"`      // App-scoped role (user, admin, etc.)
	AppRoles          map[string]string `json:"app_roles,omitempty"` // All app roles for this user
	Type              string            `json:"type"`
	Nonce             string            `json:"nonce,omitempty"`
	AtHash            string            `json:"at_hash,omitempty"`
	// Amr / Acr — OIDC authentication-methods-references / context-class-reference
	// (RFC 8176). Present when the issuing flow knows how the user authenticated.
	Amr []string `json:"amr,omitempty"`
	Acr string   `json:"acr,omitempty"`
	// Custom holds the client's mapped custom claims (A2) — see
	// AccessTokenClaims.Custom.
	Custom map[string]any `json:"-"`
}

// MarshalJSON serializes the claims with the custom (mapped) claims merged in
// at the top level, never replacing a claim the ID token already carries.
func (c IDTokenClaims) MarshalJSON() ([]byte, error) {
	type alias IDTokenClaims
	return marshalWithCustomClaims(alias(c), c.Custom)
}

// marshalWithCustomClaims serializes v and merges custom into the resulting
// object. Existing keys win, so the standard claim set is immutable from a
// client's claim-mapping policy. A custom value that cannot be serialized is
// skipped rather than failing token issuance.
func marshalWithCustomClaims(v any, custom map[string]any) ([]byte, error) {
	base, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(custom) == 0 {
		return base, nil
	}

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for name, value := range custom {
		if name == "" {
			continue
		}
		if _, taken := merged[name]; taken {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			continue
		}
		merged[name] = raw
	}

	return json.Marshal(merged)
}

// EmailTokenClaims represents email verification/reset token claims
type EmailTokenClaims struct {
	jwt.RegisteredClaims
	Email       string `json:"email"`
	Type        string `json:"type"`
	Action      string `json:"action"`
	AppID       uint   `json:"app_id,omitempty"`
	AppName     string `json:"app_name,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
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

// authnContext carries the authentication evidence (RFC 8176 amr / acr) stamped
// on the access and ID tokens. The zero value omits both claims, so flows that
// don't know how the user authenticated produce tokens identical to before.
type authnContext struct {
	amr []string
	acr string
}

// GenerateTokenSet generates a complete token set for a user.
func (ts *TokenService) GenerateTokenSet(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, nonce string, authTime int64) (*TokenSet, error) {
	return ts.generateTokenSet(user, app, role, scope, appRoles, nonce, authTime, "", authnContext{})
}

// GenerateTokenSetWithAuth is GenerateTokenSet with authentication evidence
// (RFC 8176 amr / acr) stamped on the access and ID tokens. Callers that know
// how the user authenticated (e.g. interactive login) supply the methods here;
// an empty amr/acr behaves exactly like GenerateTokenSet.
func (ts *TokenService) GenerateTokenSetWithAuth(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, nonce string, authTime int64, amr []string, acr string) (*TokenSet, error) {
	return ts.generateTokenSet(user, app, role, scope, appRoles, nonce, authTime, "", authnContext{amr: amr, acr: acr})
}

// GenerateTokenSetWithDPoP generates a complete token set whose access token is
// sender-constrained to the DPoP key thumbprint jkt via the cnf.jkt claim
// (RFC 9449). An empty jkt yields a set identical to GenerateTokenSet, so the
// token endpoint can call this unconditionally and pass the thumbprint only when
// a valid DPoP proof accompanied the request. The refresh and ID tokens are
// unchanged (refresh-token binding is a later slice).
func (ts *TokenService) GenerateTokenSetWithDPoP(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, nonce string, authTime int64, jkt string) (*TokenSet, error) {
	return ts.generateTokenSet(user, app, role, scope, appRoles, nonce, authTime, jkt, authnContext{})
}

func (ts *TokenService) generateTokenSet(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, nonce string, authTime int64, jkt string, ac authnContext) (*TokenSet, error) {
	now := time.Now()
	if authTime == 0 {
		authTime = now.Unix()
	}

	// Generate access token (bound to the DPoP key when jkt is non-empty),
	// carrying the same auth_time as the refresh/ID tokens so a resource server
	// can make freshness/step-up decisions from the access token alone.
	accessToken, err := ts.generateBoundAccessTokenAt(user, app, role, scope, appRoles, jkt, now, authTime, ac)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token (sender-constrained to the DPoP key when jkt is set).
	refreshToken, err := ts.generateRefreshToken(user, app, role, scope, appRoles, now, authTime, jkt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Generate ID token with app-scoped role (not global user.Role)
	idToken, err := ts.generateIDToken(user, app, role, appRoles, nonce, now, authTime, accessToken, ac)
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

// newAccessClaims builds the access-token claims (shared by the ordinary and
// DPoP-bound token generators).
func (ts *TokenService) newAccessClaims(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, now time.Time, authTime int64, ac authnContext) AccessTokenClaims {
	roles := []string{}
	if role != "" {
		roles = append(roles, role)
	}

	return AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   strconv.FormatUint(uint64(user.ID), 10),
			Audience:  jwt.ClaimStrings(ts.accessAudience(app)),
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
		AuthTime:     authTime,
		Amr:          ac.amr,
		Acr:          ac.acr,
		Custom:       ts.customClaims(user, app, role, model.ClaimTargetAccess),
	}
}

// GenerateBoundAccessToken generates a user access token bound to a DPoP key
// thumbprint via the `cnf.jkt` claim (RFC 9449 / RFC 7800). An empty jkt yields
// an ordinary (unbound) access token identical to generateAccessToken, so this
// is safe to call unconditionally once DPoP wiring lands.
func (ts *TokenService) GenerateBoundAccessToken(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, jkt string) (string, error) {
	return ts.generateBoundAccessTokenAt(user, app, role, scope, appRoles, jkt, time.Now(), 0, authnContext{})
}

// generateBoundAccessTokenAt is GenerateBoundAccessToken with an explicit issue
// time and end-user authentication time (auth_time, RFC 9068 §2.2.1). authTime
// of zero omits the claim, so GenerateBoundAccessToken stays byte-compatible.
func (ts *TokenService) generateBoundAccessTokenAt(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, jkt string, now time.Time, authTime int64, ac authnContext) (string, error) {
	claims := ts.newAccessClaims(user, app, role, scope, appRoles, now, authTime, ac)
	if jkt != "" {
		claims.Cnf = &Confirmation{JKT: jkt}
	}
	return ts.signToken(claims)
}

// GenerateExchangedToken mints an access token for an RFC 8693 token-exchange
// result. The subject, audience, scope and token version are supplied explicitly
// (recovered from the verified subject token, so the token version still drives
// revocation), and the act (actor) claim records who is acting — preserving
// dual-principal visibility downstream. When jkt is non-empty the token is
// DPoP-bound (cnf.jkt, RFC 9449) to the requesting client's key. It uses the
// standard short access-token TTL. This is purely the issuance primitive; the
// caller owns authorization.
func (ts *TokenService) GenerateExchangedToken(subject string, audience []string, scope string, tokenVersion int, actor *ActClaim, jkt string) (token string, expiresIn int, err error) {
	return ts.GenerateExchangedTokenWithTTL(subject, audience, scope, tokenVersion, actor, jkt, 0)
}

// GenerateExchangedTokenWithTTL is GenerateExchangedToken with an explicit
// lifetime. It lets the caller tighten the time-box for sensitive exchanges
// (e.g. impersonation, EPIC-17) below the standard access-token TTL. A ttl of
// zero (or negative) falls back to the standard access-token TTL, so callers
// that don't care about the lifetime keep the default behaviour.
func (ts *TokenService) GenerateExchangedTokenWithTTL(subject string, audience []string, scope string, tokenVersion int, actor *ActClaim, jkt string, ttl time.Duration) (token string, expiresIn int, err error) {
	if ttl <= 0 {
		ttl = ts.accessTokenTTL
	}
	now := time.Now()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings(audience),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.New().String(),
		},
		Scope:        scope,
		Type:         "access",
		TokenVersion: tokenVersion,
		Act:          actor,
	}
	if jkt != "" {
		claims.Cnf = &Confirmation{JKT: jkt}
	}
	signed, serr := ts.signToken(claims)
	if serr != nil {
		return "", 0, serr
	}
	return signed, int(ttl.Seconds()), nil
}

// generateRefreshToken generates a refresh token, optionally sender-constrained
// to a DPoP key thumbprint (cnf.jkt) when jkt is non-empty.
func (ts *TokenService) generateRefreshToken(user *model.User, app *model.App, role string, scope string, appRoles map[string]string, now time.Time, authTime int64, jkt string) (string, error) {
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
	if jkt != "" {
		claims.Cnf = &Confirmation{JKT: jkt}
	}

	return ts.signToken(claims)
}

// generateIDToken generates an OpenID Connect ID token
func (ts *TokenService) generateIDToken(user *model.User, app *model.App, role string, appRoles map[string]string, nonce string, now time.Time, authTime int64, accessToken string, ac authnContext) (string, error) {
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
		Role:              role,     // App-scoped role (e.g., "admin", "user")
		AppRoles:          appRoles, // All app roles for this user
		Type:              "id_token",
		Nonce:             nonce,
		AtHash:            atHash,
		Amr:               ac.amr,
		Acr:               ac.acr,
		Custom:            ts.customClaims(user, app, role, model.ClaimTargetID),
	}

	return ts.signToken(claims)
}

// AppContext contains optional app information for email tokens
type AppContext struct {
	AppID       uint
	AppName     string
	RedirectURI string
}

// GenerateEmailVerificationToken generates an email verification token
func (ts *TokenService) GenerateEmailVerificationToken(email string, userID uint, appCtx *AppContext) (string, error) {
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

	if appCtx != nil {
		claims.AppID = appCtx.AppID
		claims.AppName = appCtx.AppName
		claims.RedirectURI = appCtx.RedirectURI
	}

	return ts.signToken(claims)
}

// GeneratePasswordResetToken generates a password reset token
func (ts *TokenService) GeneratePasswordResetToken(email string, userID uint, appCtx *AppContext) (string, error) {
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

	if appCtx != nil {
		claims.AppID = appCtx.AppID
		claims.AppName = appCtx.AppName
		claims.RedirectURI = appCtx.RedirectURI
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
		// A2: a service-account token has no user, so only the app-scoped and
		// literal sources resolve — user-sourced mappings yield no claim.
		Custom: ts.customClaims(nil, app, "", model.ClaimTargetAccess),
	}

	return ts.signToken(claims)
}

// signToken signs a token via the configured Signer. The signing backend
// (local RSA key today, KMS/HSM in future per RFC-002) is abstracted behind
// the Signer interface; the default signer reproduces the prior RS256 + kid
// behaviour exactly.
func (ts *TokenService) signToken(claims jwt.Claims) (string, error) {
	return ts.signer.SignToken(claims)
}

// verifyToken is a generic token verification function that consolidates common logic.
//
// M-03 fix: the Keyfunc now selects the public key by the token's "kid" header
// so that tokens signed before a key rotation can still be verified using the
// retired key ring, instead of failing with ErrTokenSignature.
//
// RFC-002 hardening: verification is pinned to an explicit algorithm allow-list
// (exactly "RS256") via jwt.WithValidMethods. This is enforced by the parser
// before the Keyfunc runs, so any other alg — RS384/RS512, "none", or an HMAC
// algorithm (alg-confusion) — is rejected regardless of the key returned. The
// Keyfunc's *jwt.SigningMethodRSA assertion is retained as defense in depth.
//
// It also enforces two claim invariants at the parser level: the issuer must
// equal this server's configured issuer (jwt.WithIssuer), so a token minted by
// a different issuer is rejected even if its signature would otherwise verify;
// and an expiry is mandatory (jwt.WithExpirationRequired), so a token with no
// exp can never be treated as non-expiring.
func (ts *TokenService) verifyToken(tokenString string, claims jwt.Claims) error {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		pub, err := ts.keyManager.GetPublicKeyByID(kid)
		if err != nil {
			// Fall back to current key for tokens that predate KID support
			// (e.g. tokens issued before migration to UUIDs with no kid header).
			return ts.keyManager.GetPublicKey(), nil
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(ts.issuer), jwt.WithExpirationRequired())

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
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) || errors.Is(err, jwt.ErrTokenRequiredClaimMissing) {
			return ErrTokenClaimsInvalid
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

// VerifyIDToken verifies an OpenID Connect ID token and returns its claims.
// Used by EndSession to validate the id_token_hint (M-06).
func (ts *TokenService) VerifyIDToken(tokenString string) (*IDTokenClaims, error) {
	claims := &IDTokenClaims{}
	if err := ts.verifyToken(tokenString, claims); err != nil {
		return nil, err
	}

	if claims.Type != "id_token" {
		return nil, fmt.Errorf("%w: expected id_token, got %s", ErrTokenInvalidType, claims.Type)
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
