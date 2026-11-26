package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/pkg/logger"
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
//	POST /api/profile/mfa/disable  – disable MFA (requires password + code, P3-9)
type MFAHandler struct {
	mfaService service.MFAService
	reverifier MFAReverifier // re-proves the account before Disable
}

// MFAReverifier re-proves an account before its second factor is turned off:
// the password (when given and the account has one) and a TOTP or recovery
// code, each failure counting toward the account lockout. The auth service
// implements it (ReverifyForMFAChange).
type MFAReverifier interface {
	ReverifyForMFAChange(ctx context.Context, userID uint, password *string, code string) error
}

// NewMFAHandler creates the handler. reverifier re-proves the account before
// MFA is disabled; if nil, Disable fails closed.
func NewMFAHandler(mfaService service.MFAService, reverifier MFAReverifier) *MFAHandler {
	return &MFAHandler{mfaService: mfaService, reverifier: reverifier}
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

	// Only surface a remaining-code count for enrolled users (it is always 0
	// before enrollment).
	remaining := 0
	if enabled {
		remaining, err = h.mfaService.RemainingRecoveryCodes(r.Context(), userID)
		if err != nil {
			logger.Warnf("mfa: recovery-code count for user %d: %v", userID, err)
			writeError(w, "could not read MFA status", http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, dto.MFAStatusResponse{Enabled: enabled, RecoveryCodesRemaining: remaining})
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

// RecoveryCodes handles POST /api/profile/mfa/recovery-codes — it (re)generates
// the user's one-time backup codes and returns them once. Requires MFA enabled.
func (h *MFAHandler) RecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	codes, err := h.mfaService.GenerateRecoveryCodes(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFANotEnrolled):
			writeError(w, "MFA is not enabled", http.StatusConflict)
		default:
			logger.Warnf("mfa: generate recovery codes for user %d: %v", userID, err)
			writeError(w, "could not generate recovery codes", http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, dto.MFARecoveryCodesResponse{RecoveryCodes: codes})
}

// Disable handles POST /api/profile/mfa/disable.
//
// P3-9: a bearer token alone (which may have been minted long ago, or stolen)
// must not be enough to strip the second factor. The caller re-proves the
// account: the current password when the account has one, plus a valid TOTP
// code or an unused recovery code. Every failure returns the same 401 so the
// response does not reveal which factor was wrong.
func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req dto.MFADisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Code == "" {
		writeError(w, "code is required", http.StatusBadRequest)
		return
	}

	if h.reverifier == nil {
		logger.Warnf("mfa: disable for user %d: no re-verifier wired, refusing", userID)
		writeError(w, "could not disable MFA", http.StatusInternalServerError)
		return
	}
	// The password (accounts created through invite or magic-link flows may
	// have none) and a TOTP or recovery code; each failure counts toward the
	// account lockout, so a bearer token is not a way to guess them.
	switch err := h.reverifier.ReverifyForMFAChange(r.Context(), userID, &req.Password, req.Code); {
	case err == nil:
	case errors.Is(err, service.ErrMFANotEnrolled):
		writeError(w, "MFA is not enabled", http.StatusConflict)
		return
	case errors.Is(err, service.ErrAccountLocked):
		writeError(w, "account is locked", http.StatusForbidden)
		return
	case errors.Is(err, service.ErrInvalidCredentials), errors.Is(err, service.ErrMFAInvalidCode),
		errors.Is(err, service.ErrMFARequired), errors.Is(err, service.ErrUserNotFound):
		writeError(w, "re-authentication failed", http.StatusUnauthorized)
		return
	default:
		logger.Warnf("mfa: re-verify before disable for user %d: %v", userID, err)
		writeError(w, "could not disable MFA", http.StatusInternalServerError)
		return
	}

	if err := h.mfaService.Disable(r.Context(), userID); err != nil {
		logger.Warnf("mfa: disable for user %d: %v", userID, err)
		writeError(w, "could not disable MFA", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
