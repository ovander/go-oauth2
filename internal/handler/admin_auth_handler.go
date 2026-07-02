package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/service"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// AdminAuthHandler handles authentication for the admin portal
type AdminAuthHandler struct {
	authService service.AuthService
	userService service.UserService
	autoDefense *service.AutoDefenseService
	// reauth backs POST /api/admin/elevate (step-up). Optional; nil disables the
	// endpoint. Wired by bootstrap. Tier-0 admin session hardening.
	reauth service.Reauthenticator
	// passwordLoginDisabled refuses the legacy /api/admin/login password flow
	// when true. Zero value (false) keeps it enabled — backward compatible.
	passwordLoginDisabled bool
}

// SetPasswordLoginDisabled toggles the deprecated /api/admin/login password
// flow. true refuses it (the admin console must use Authorization Code + PKCE).
func (h *AdminAuthHandler) SetPasswordLoginDisabled(disabled bool) {
	h.passwordLoginDisabled = disabled
}

// NewAdminAuthHandler creates a new admin auth handler
func NewAdminAuthHandler(authService service.AuthService, userService service.UserService) *AdminAuthHandler {
	return &AdminAuthHandler{
		authService: authService,
		userService: userService,
	}
}

// SetReauthenticator wires the step-up re-authentication backend for
// POST /api/admin/elevate. Without it the endpoint returns 501.
func (h *AdminAuthHandler) SetReauthenticator(r service.Reauthenticator) { h.reauth = r }

// POST /api/admin/elevate
// Step-up: the already-authenticated admin re-presents their password (and MFA,
// if enrolled) to obtain a fresh-auth_time access token, satisfying the
// freshness gate (middleware.RequireFreshAuth) on destructive routes. The
// returned access token replaces the one the SPA sends on those calls; the
// session's refresh token is unchanged (no refresh token is returned).
func (h *AdminAuthHandler) Elevate(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.reauth == nil {
		writeError(w, "step-up is not configured", http.StatusNotImplemented)
		return
	}

	var req dto.ElevateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		writeError(w, "password is required", http.StatusBadRequest)
		return
	}

	resp, err := h.reauth.ReAuthenticate(r.Context(), userID, req.Password, req.MFACode)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, "invalid credentials", http.StatusUnauthorized)
		case errors.Is(err, service.ErrMFARequired):
			writeError(w, "mfa_required", http.StatusUnauthorized)
		case errors.Is(err, service.ErrMFAInvalidCode):
			writeError(w, "invalid mfa code", http.StatusUnauthorized)
		default:
			writeError(w, "elevation failed", http.StatusBadRequest)
		}
		return
	}

	writeJSON(w, resp)
}

// SetAutoDefenseService sets the auto-defense service for IP-based threat detection
func (h *AdminAuthHandler) SetAutoDefenseService(autoDefense *service.AutoDefenseService) {
	h.autoDefense = autoDefense
}

// POST /api/admin/login
// Admin portal login - only allows superadmins
func (h *AdminAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// RFC 8594: signal that the password login flow is deprecated in favour of
	// the admin console's Authorization Code + PKCE flow.
	w.Header().Set("Deprecation", "true")

	if h.passwordLoginDisabled {
		writeError(w, "password_login_disabled", http.StatusForbidden)
		return
	}

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

		// M2 fix: errors.Is, not equality — AdminLogin wraps ErrAccountLocked
		// and ErrUserNotVerified (fmt.Errorf("%w: ...")), which an equality
		// switch misses, falling through to default and leaking err.Error().
		// M1 fix: the default branch now returns a static message; the real
		// error is logged, never forwarded to the client.
		switch {
		case errors.Is(err, service.ErrAccountLocked):
			writeError(w, "account is locked", http.StatusForbidden)
		case errors.Is(err, service.ErrUserNotVerified):
			writeError(w, "email not verified", http.StatusForbidden)
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, "invalid credentials", http.StatusUnauthorized)
		case errors.Is(err, service.ErrNotAdmin):
			writeError(w, "admin access required", http.StatusForbidden)
		case errors.Is(err, service.ErrMFARequired):
			// Password was correct; the client must resubmit with mfa_code.
			writeError(w, "mfa_required", http.StatusUnauthorized)
		case errors.Is(err, service.ErrMFAInvalidCode):
			writeError(w, "invalid mfa code", http.StatusUnauthorized)
		case errors.Is(err, service.ErrMFAEnrollmentRequired):
			// Policy requires admins to enroll MFA before they can log in.
			writeError(w, "mfa_enrollment_required", http.StatusForbidden)
		default:
			logger.Warnf("admin login failed: %v", err)
			writeError(w, "login failed", http.StatusBadRequest)
		}
		return
	}

	// Record successful login (clears failed attempt tracking)
	if h.autoDefense != nil {
		h.autoDefense.RecordSuccessfulLogin(clientIP)
	}

	writeJSON(w, response)
}

// POST /api/admin/change-password
// Authenticated password change. Reachable even when the admin is flagged
// MustChangePassword (the enforcement middleware exempts this path), so it is
// the way out of a forced-change state. On success all the admin's tokens are
// revoked (token-version bump) and they must re-authenticate.
func (h *AdminAuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req dto.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, "current_password and new_password are required", http.StatusBadRequest)
		return
	}

	if err := h.authService.ChangePassword(r.Context(), userID, req.CurrentPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, "current password is incorrect", http.StatusUnauthorized)
		default:
			// Validation failures (weak password, same-as-current) are client
			// errors; never leak raw internal error strings beyond their message.
			writeError(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	// Tokens were revoked server-side; the client must re-authenticate.
	writeJSON(w, dto.MessageResponse{Message: "Password changed successfully; please log in again"})
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
