package dto

import "time"

// Request DTOs

type SignupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	ClientID string `json:"client_id"`
}

type LoginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	AppClientID string `json:"app_client_id"`
	// MFACode is the TOTP code, required only when the user has MFA enabled.
	// Omitted on the first request; the server replies with an "mfa_required"
	// error and the client retries with the code. RFC-011 / EPIC-9.
	MFACode string `json:"mfa_code,omitempty"`
}

// AdminLoginRequest is for admin portal login (no app context required)
type AdminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// MFACode is the TOTP code, required only when the admin has MFA enabled.
	MFACode string `json:"mfa_code,omitempty"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	// Token can be in header or body
}

type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// ChangePasswordRequest is the body for an authenticated password change. Used
// to satisfy a pending MustChangePassword flag (Tier-0 admin session hardening).
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ElevateRequest is the body for admin step-up (POST /api/admin/elevate). The
// admin is already authenticated (Bearer); they re-present their password (and
// MFA, if enrolled) to obtain a fresh-auth_time access token for destructive
// operations. Tier-0 admin session hardening.
type ElevateRequest struct {
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type AcceptInviteRequest struct {
	Token    string `json:"token"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

// Response DTOs

type SignupResponse struct {
	UserID    uint   `json:"user_id"`
	Message   string `json:"message"`
	VerifyURL string `json:"verify_url,omitempty"` // Only in dev/test
}

type LoginResponse struct {
	AccessToken        string            `json:"access_token"`
	RefreshToken       string            `json:"refresh_token"`
	IDToken            string            `json:"id_token"`
	TokenType          string            `json:"token_type"`
	ExpiresIn          int               `json:"expires_in"`
	UserID             uint              `json:"user_id"`
	App                *AppResponse      `json:"app,omitempty"`
	Roles              []string          `json:"roles"`
	AppRoles           map[string]string `json:"app_roles"`
	MustChangePassword bool              `json:"must_change_password,omitempty"`
	// AuthTime, AMR and ACR describe this sign-in (when, and how). They are
	// not serialized: the hosted login carries them into the authorization
	// code, so the code's tokens report the real authentication.
	AuthTime int64    `json:"-"`
	AMR      []string `json:"-"`
	ACR      string   `json:"-"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type UserInfoResponse struct {
	Sub               string            `json:"sub"`
	Email             string            `json:"email"`
	EmailVerified     bool              `json:"email_verified"`
	Name              string            `json:"name"`
	PreferredUsername string            `json:"preferred_username"`
	Picture           string            `json:"picture,omitempty"` // OIDC picture: the avatar URL, when set
	Role              string            `json:"role"`
	AppRoles          map[string]string `json:"app_roles"`
}

type InviteValidationResponse struct {
	Valid     bool      `json:"valid"`
	Email     string    `json:"email,omitempty"`
	AppName   string    `json:"app_name,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// MagicLinkRequest is the body for POST /api/apps/{app_id}/service/magic-link.
// The endpoint is service-account protected — the app is already identified by
// the URL parameter and the client_credentials token, so no client_id is needed
// in the body.  The response is always the same opaque message regardless of
// whether the email exists, to prevent user-enumeration.
type MagicLinkRequest struct {
	Email string `json:"email"`
}

// MagicLinkResponse is the body returned after a magic-link is requested.
type MagicLinkResponse struct {
	Message string `json:"message"`
	// MagicURL is only populated in development mode so that tests can
	// exercise the full flow without a real mail server.
	MagicURL string `json:"magic_url,omitempty"`
}

// MagicLinkVerifyRequest is the body for POST /api/auth/magic-link/verify.
// client_id is required here because the verify endpoint is public — the app
// context is not available from a service account token at this point.
type MagicLinkVerifyRequest struct {
	Token    string `json:"token"`
	ClientID string `json:"client_id"`
}
