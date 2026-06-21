package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/service"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

type AuthHandler struct {
	authService  service.AuthService
	userService  service.UserService
	emailService service.EmailService
	autoDefense  *service.AutoDefenseService
	environment  string
	issuer       string
}

func NewAuthHandler(authService service.AuthService, userService service.UserService, emailService service.EmailService, environment, issuer string) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		userService:  userService,
		emailService: emailService,
		environment:  environment,
		issuer:       issuer,
	}
}

// SetAutoDefenseService sets the auto-defense service for IP-based threat detection
func (h *AuthHandler) SetAutoDefenseService(autoDefense *service.AutoDefenseService) {
	h.autoDefense = autoDefense
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

	// MED-03 fix: only expose the raw verification token in explicitly local
	// development ("development" / "dev").  Test environments are NOT included
	// because a staging server may be internet-accessible yet have ENV=test set
	// by accident.  In CI tests inject the token via the audit log or a
	// dedicated test helper rather than relying on this response field.
	if h.environment == "development" || h.environment == "dev" {
		response.VerifyURL = h.issuer + "/api/auth/verify-email?token=" + verifyToken
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, response)
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

	writeJSON(w, dto.MessageResponse{Message: "Email verified successfully"})
}

// POST /api/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.AppClientID == "" {
		writeError(w, "email, password, and app_client_id are required", http.StatusBadRequest)
		return
	}

	clientIP := middleware.GetClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	response, err := h.authService.Login(r.Context(), req)
	if err != nil {
		// Record failed login for auto-defense
		if h.autoDefense != nil {
			h.autoDefense.RecordFailedLogin(r.Context(), clientIP, userAgent)
		}

		switch err {
		case service.ErrAccountLocked:
			writeError(w, "account is locked", http.StatusForbidden)
		case service.ErrUserNotVerified:
			writeError(w, "email not verified", http.StatusForbidden)
		case service.ErrInvalidCredentials:
			writeError(w, "invalid credentials", http.StatusUnauthorized)
		case service.ErrMFARequired:
			// Password was correct; the client must resubmit with mfa_code.
			writeError(w, "mfa_required", http.StatusUnauthorized)
		case service.ErrMFAInvalidCode:
			writeError(w, "invalid mfa code", http.StatusUnauthorized)
		default:
			writeError(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	// Record successful login (clears failed attempt tracking)
	if h.autoDefense != nil {
		h.autoDefense.RecordSuccessfulLogin(clientIP)
	}

	writeJSON(w, response)
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

	writeJSON(w, response)
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

	writeJSON(w, dto.MessageResponse{Message: "Logged out successfully"})
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

	// Request password reset (no app context in API flow)
	token, _ := h.authService.RequestPasswordReset(r.Context(), req.Email, nil)

	// Send email if token was generated
	if token != "" && h.emailService != nil {
		resetURL := h.issuer + "/auth/reset-password?token=" + token
		// Get user name for email
		user, _ := h.userService.GetByEmail(r.Context(), req.Email)
		name := req.Email
		if user != nil {
			name = user.Name
		}
		if err := h.emailService.SendPasswordResetEmail(req.Email, name, "", resetURL); err != nil {
			logger.Warnf("ForgotPassword: failed to send password reset email to %s: %v", req.Email, err)
		}
	}

	// Always return success to prevent email enumeration
	writeJSON(w, dto.MessageResponse{
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

	writeJSON(w, dto.MessageResponse{Message: "Password reset successfully"})
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

	writeJSON(w, response)
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

	response, err := h.authService.AcceptInvite(r.Context(), req.Token, req.Name, req.Password)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, response)
}

// GET /api/userinfo
func (h *AuthHandler) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.userService.GetByID(r.Context(), userID)
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	response := dto.UserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Name:       user.Name,
		Role:       string(user.Role),
		IsVerified: user.IsVerified,
		Title:      user.Title,
		Division:   user.Division,
		Company:    user.Company,
		Country:    user.Country,
		Phone:      user.Phone,
		JobTitle:   user.JobTitle,
		Department: user.Department,
		Language:   user.Language,
		Timezone:   user.Timezone,
		LastLogin:  user.LastLogin,
		CreatedAt:  user.CreatedAt,
	}

	writeJSON(w, response)
}

func writeError(w http.ResponseWriter, message string, status int) {
	w.WriteHeader(status)
	writeJSON(w, dto.ErrorResponse{Error: message})
}
