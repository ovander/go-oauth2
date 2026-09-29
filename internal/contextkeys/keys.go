package contextkeys

type contextKey string

const (
	UserIDKey            contextKey = "user_id"
	UserRoleKey          contextKey = "user_role"
	CurrentUserKey       contextKey = "current_user"
	JWTClaimsKey         contextKey = "jwt_claims"
	AppIDKey             contextKey = "app_id"
	RequestIDKey         contextKey = "request_id"
	IPAddressKey         contextKey = "ip_address"
	ServiceAccountAppKey contextKey = "service_account_app"
	// DPoPJKTKey carries the verified DPoP JWK thumbprint (jkt) of the proof that
	// accompanied the request, so the token endpoint can sender-constrain the
	// issued access token (RFC 9449). Empty/absent when no valid proof was sent.
	DPoPJKTKey contextKey = "dpop_jkt"
	// UserAgentKey carries the request's User-Agent header, set with IPAddressKey
	// by middleware.ClientIP, so audit rows written from services are attributed.
	UserAgentKey contextKey = "user_agent"
)
