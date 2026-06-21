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

// MFAHandler serves the authenticated self-service TOTP MFA endpoints. A user
// can only ever read or change their own MFA state (the user id comes from the
// authenticated request context, never from the request body).
//
// Routes (all under /api/profile/mfa, protected by AuthMiddleware):
//
//	GET  /api/profile/mfa          – report whether MFA is enabled
//	POST /api/profile/mfa/enroll   – begin enrollment (returns secret + otpauth URI)
//	POST /api/profile/mfa/confirm  – confirm enrollment with a code
//	POST /api/profile/mfa/disable  – disable MFA
type MFAHandler struct {
	mfaService service.MFAService
}

// NewMFAHandler creates the handler.
func NewMFAHandler(mfaService service.MFAService) *MFAHandler {
	return &MFAHandler{mfaService: mfaService}
}

// Status handles GET /api/profile/mfa.
func (h *MFAHandler) Status(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	enabled, err := h.mfaService.IsEnabled(r.Context(), userID)
	if err != nil {
		logger.Warnf("mfa: status for user %d: %v", userID, err)
		writeError(w, "could not read MFA status", http.StatusInternalServerError)
		return
	}
	writeJSON(w, dto.MFAStatusResponse{Enabled: enabled})
}

// Enroll handles POST /api/profile/mfa/enroll.
func (h *MFAHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	secret, uri, err := h.mfaService.BeginEnrollment(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFAAlreadyEnabled):
			writeError(w, "MFA is already enabled", http.StatusConflict)
		default:
			logger.Warnf("mfa: begin enrollment for user %d: %v", userID, err)
			writeError(w, "could not begin MFA enrollment", http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, dto.MFAEnrollResponse{Secret: secret, ProvisioningURI: uri})
}

// Confirm handles POST /api/profile/mfa/confirm.
func (h *MFAHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req dto.MFAConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	err := h.mfaService.ConfirmEnrollment(r.Context(), userID, req.Code)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, service.ErrMFAInvalidCode):
		writeError(w, "invalid code", http.StatusBadRequest)
	case errors.Is(err, service.ErrMFANotEnrolled):
		writeError(w, "no pending enrollment; call enroll first", http.StatusConflict)
	default:
		logger.Warnf("mfa: confirm enrollment for user %d: %v", userID, err)
		writeError(w, "could not confirm MFA enrollment", http.StatusInternalServerError)
	}
}

// Disable handles POST /api/profile/mfa/disable.
func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.mfaService.Disable(r.Context(), userID); err != nil {
		logger.Warnf("mfa: disable for user %d: %v", userID, err)
		writeError(w, "could not disable MFA", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
