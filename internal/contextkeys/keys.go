package contextkeys

type contextKey string

const (
	UserIDKey      contextKey = "user_id"
	UserRoleKey    contextKey = "user_role"
	CurrentUserKey contextKey = "current_user"
	JWTClaimsKey   contextKey = "jwt_claims"
	AppIDKey       contextKey = "app_id"
	RequestIDKey   contextKey = "request_id"
	IPAddressKey   contextKey = "ip_address"
)
