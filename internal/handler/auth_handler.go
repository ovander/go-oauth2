package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

type AuthHandler struct {
	authService service.AuthService
	environment string
	issuer      string
}

func NewAuthHandler(authService service.AuthService, environment, issuer string) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		environment: environment,
		issuer:      issuer,
	}
}

// POST /api/auth/signup
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req dto.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.Name == "" || req.ClientID == "" {
		writeError(w, "email, name, password, and client_id are required", http.StatusBadRequest)
		return
	}

	user, verifyToken, err := h.authService.Signup(r.Context(), req)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := dto.SignupResponse{
		UserID:  user.ID,
		Message: "Please check your email to verify your account",
	}

	// Include verify URL in dev/test environments
	if h.environment == "development" || h.environment == "test" {
		response.VerifyURL = h.issuer + "/api/auth/verify-email?token=" + verifyToken
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// GET /api/auth/verify-email
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, "token is required", http.StatusBadRequest)
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), token); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(dto.MessageResponse{Message: "Email verified successfully"})
}

// POST /api/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	response, err := h.authService.Login(r.Context(), req)
	if err != nil {
		switch err {
		case service.ErrAccountLocked:
			writeError(w, "account is locked", http.StatusForbidden)
		case service.ErrUserNotVerified:
			writeError(w, "email not verified", http.StatusForbidden)
		case service.ErrInvalidCredentials:
			writeError(w, "invalid credentials", http.StatusUnauthorized)
		default:
			writeError(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	json.NewEncoder(w).Encode(response)
}

// POST /api/auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req dto.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		writeError(w, "refresh_token is required", http.StatusBadRequest)
		return
	}

	response, err := h.authService.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(response)
}

// POST /api/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.authService.Logout(r.Context(), userID); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(dto.MessageResponse{Message: "Logged out successfully"})
}

// POST /api/auth/request-password-reset
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req dto.RequestPasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		writeError(w, "email is required", http.StatusBadRequest)
		return
	}

	// Always return success to prevent email enumeration
	h.authService.RequestPasswordReset(r.Context(), req.Email)

	json.NewEncoder(w).Encode(dto.MessageResponse{
		Message: "If an account exists with this email, a password reset link has been sent",
	})
}

// POST /api/auth/reset-password
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req dto.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Token == "" || req.Password == "" {
		writeError(w, "token and password are required", http.StatusBadRequest)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(dto.MessageResponse{Message: "Password reset successfully"})
}

// GET /api/auth/invite
func (h *AuthHandler) ValidateInvite(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, "token is required", http.StatusBadRequest)
		return
	}

	response, err := h.authService.ValidateInviteToken(r.Context(), token)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(response)
}

// POST /api/auth/invite
func (h *AuthHandler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	var req dto.AcceptInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Token == "" || req.Password == "" {
		writeError(w, "token and password are required", http.StatusBadRequest)
		return
	}

	response, err := h.authService.AcceptInvite(r.Context(), req.Token, req.Password)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(response)
}

// GET /api/auth/api_userinfo
func (h *AuthHandler) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// TODO: Implement user info retrieval with proper claims
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": userID,
	})
}

func writeError(w http.ResponseWriter, message string, status int) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(dto.ErrorResponse{Error: message})
}
