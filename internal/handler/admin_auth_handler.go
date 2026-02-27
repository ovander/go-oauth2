package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// AdminAuthHandler handles authentication for the admin portal
type AdminAuthHandler struct {
	authService service.AuthService
	userService service.UserService
	autoDefense *service.AutoDefenseService
}

// NewAdminAuthHandler creates a new admin auth handler
func NewAdminAuthHandler(authService service.AuthService, userService service.UserService) *AdminAuthHandler {
	return &AdminAuthHandler{
		authService: authService,
		userService: userService,
	}
}

// SetAutoDefenseService sets the auto-defense service for IP-based threat detection
func (h *AdminAuthHandler) SetAutoDefenseService(autoDefense *service.AutoDefenseService) {
	h.autoDefense = autoDefense
}

// POST /api/admin/login
// Admin portal login - only allows superadmins
func (h *AdminAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.AdminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	clientIP := middleware.GetClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	response, err := h.authService.AdminLogin(r.Context(), req)
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
		case service.ErrNotAdmin:
			writeError(w, "admin access required", http.StatusForbidden)
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

// GET /api/admin/profile
// Get the current admin's profile
func (h *AdminAuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
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

	writeJSON(w, dto.UserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Name:       user.Name,
		Role:       string(user.Role),
		IsVerified: user.IsVerified,
		CreatedAt:  user.CreatedAt,
	})
}
