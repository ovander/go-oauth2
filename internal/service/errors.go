package service

import "errors"

// Common service errors
var (
	// User errors
	ErrUserNotFound               = errors.New("user not found")
	ErrEmailAlreadyExists         = errors.New("email already exists")
	ErrInvalidCredentials         = errors.New("invalid credentials")
	ErrAccountLocked              = errors.New("account is locked")
	ErrUserNotVerified            = errors.New("user email not verified")
	ErrNotAdmin                   = errors.New("admin access required")
	ErrCannotDeleteSelf           = errors.New("cannot delete your own account")
	ErrCannotDeleteLastSuperadmin = errors.New("cannot delete the last superadmin")

	// MFA login step-up. ErrMFARequired signals that the password was correct but
	// a second factor (TOTP code) is needed to complete login; the client should
	// prompt for the code and retry. (ErrMFAInvalidCode is defined in
	// mfa_service.go.)
	ErrMFARequired = errors.New("mfa: code required")

	// App errors
	ErrAppNotFound        = errors.New("app not found")
	ErrClientIDExists     = errors.New("client ID already exists")
	ErrInvalidRedirectURI = errors.New("invalid redirect URI")

	// Role errors
	ErrRoleNotFound      = errors.New("role not found")
	ErrRoleAlreadyExists = errors.New("user already has a role in this app")
	ErrCannotRemoveSelf  = errors.New("cannot remove yourself from the app")

	// Token errors
	ErrInvalidToken     = errors.New("invalid or expired token")
	ErrTokenAlreadyUsed = errors.New("token has already been used")
)
