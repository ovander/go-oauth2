package dto

// OAuth Request DTOs

type AuthorizeRequest struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	// LOW-02: max_age (OIDC Core §3.1.2.1) — maximum age in seconds since
	// the user last authenticated.  When present the Authorize handler checks
	// the session's auth_time and forces re-authentication if the session is
	// older than max_age seconds.  -1 means not specified by the client.
	MaxAge int `json:"max_age,omitempty"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type IntrospectRequest struct {
	Token        string `json:"token"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

type RevokeRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
}

// OAuth Response DTOs

type TokenResponse struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	IDToken      string            `json:"id_token,omitempty"`
	TokenType    string            `json:"token_type"`
	ExpiresIn    int               `json:"expires_in"`
	Scope        string            `json:"scope,omitempty"`
	Roles        []string          `json:"roles,omitempty"`
	AppRoles     map[string]string `json:"app_roles,omitempty"`
	// IssuedTokenType is the RFC 8693 token-exchange response field identifying
	// the type of the issued token (set only for token-exchange responses).
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	// Aud is the token's audience (RFC 7662 §2.2) — the resource identifiers it
	// is intended for. A resource server introspecting a token verifies its own
	// identifier appears here (RFC-001 / EPIC-7). Carries the client_id plus any
	// registered audiences when AUDIENCE_MODE=dual.
	Aud []string `json:"aud,omitempty"`
	// AuthTime is the end-user's last authentication time (RFC 9068 §2.2.1 /
	// OIDC auth_time), surfaced so a resource server introspecting a token can
	// make freshness/step-up decisions. Omitted when the token carries no
	// auth_time (e.g. client-credentials or token-exchange results).
	AuthTime int64 `json:"auth_time,omitempty"`
	// Amr / Acr are the authentication methods / context class (RFC 8176),
	// surfaced so a resource server can gate on authentication strength (e.g.
	// require `mfa`). Present when the issuing flow recorded them.
	Amr []string `json:"amr,omitempty"`
	Acr string   `json:"acr,omitempty"`
	// Cnf is the RFC 7662 §2.2 / RFC 9449 §7 confirmation claim, present when the
	// token is sender-constrained (DPoP). It lets a resource server learn the
	// `jkt` it must match against the request's DPoP proof.
	Cnf *CnfClaim `json:"cnf,omitempty"`
	// Act is the RFC 8693 §4.1 actor claim, present on tokens minted via token
	// exchange (delegation/impersonation). It lets a resource server see who is
	// acting on the subject's behalf.
	Act *ActClaim `json:"act,omitempty"`
}

// CnfClaim is the introspection confirmation claim (carries the DPoP `jkt`).
type CnfClaim struct {
	JKT string `json:"jkt,omitempty"`
}

// ActClaim is the introspection actor claim (RFC 8693 §4.1), nestable to
// represent a delegation chain.
type ActClaim struct {
	Sub string    `json:"sub"`
	Act *ActClaim `json:"act,omitempty"`
}

type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	// AcrValuesSupported advertises the authentication context class values the
	// OP can assert (RFC 8176 / OIDC Discovery): "pwd" (password) and "mfa"
	// (multi-factor). Omitted when empty.
	AcrValuesSupported []string `json:"acr_values_supported,omitempty"`
	// DPoPSigningAlgValuesSupported advertises DPoP support (RFC 9449 §5.1).
	// Omitted when the server does not have DPoP enabled.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}
