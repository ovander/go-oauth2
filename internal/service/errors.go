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
	// ErrInvalidUserAttributes indicates an attribute set (A2) that exceeds the
	// count/name/size bounds, or that cannot be serialized.
	ErrInvalidUserAttributes = errors.New("invalid user attributes")

	// MFA login step-up. ErrMFARequired signals that the password was correct but
	// a second factor (TOTP code) is needed to complete login; the client should
	// prompt for the code and retry. (ErrMFAInvalidCode is defined in
	// mfa_service.go.) ErrMFAEnrollmentRequired signals that an MFA-mandatory
	// admin has not enrolled a second factor and must do so before logging in.
	ErrMFARequired           = errors.New("mfa: code required")
	ErrMFAEnrollmentRequired = errors.New("mfa: enrollment required")

	// App errors
	ErrAppNotFound        = errors.New("app not found")
	ErrAppInactive        = errors.New("app is deactivated")
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
