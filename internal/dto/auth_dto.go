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
}

// AdminLoginRequest is for admin portal login (no app context required)
type AdminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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
