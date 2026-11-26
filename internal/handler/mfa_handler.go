package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
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
//	POST /api/profile/mfa/confirm  – confirm enrollment with a code (returns the first recovery codes)
//	POST /api/profile/mfa/disable  – disable MFA (requires password + code, P3-9)
//	POST /api/profile/mfa/recovery-codes – replace the recovery codes (password + code under enforce)
type MFAHandler struct {
	mfaService service.MFAService
	reverifier MFAReverifier // re-proves the account before Disable

	// recoveryReverifyMode is MFA_RECOVERY_CODES_REVERIFY_MODE and
	// recoveryReverifyAudit records what it observes or refuses. See
	// SetRecoveryCodesReverify.
	recoveryReverifyMode  string
	recoveryReverifyAudit service.SecurityAuditService
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

// SetRecoveryCodesReverify sets MFA_RECOVERY_CODES_REVERIFY_MODE for POST
// /api/profile/mfa/recovery-codes: "observe" audits whether the request
// carried a password and a code (without checking them), and "enforce"
// requires them and checks them as Disable does, each failure counting toward
// the account lockout. Any other mode changes nothing: a bearer token alone
// replaces the codes.
func (h *MFAHandler) SetRecoveryCodesReverify(mode string, audit service.SecurityAuditService) {
	h.recoveryReverifyMode = mode
	h.recoveryReverifyAudit = audit
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
		// The first recovery codes come with the confirmation: the code just
		// accepted cannot be used again, so asking for them afterwards would
		// need another one under MFA_RECOVERY_CODES_REVERIFY_MODE=enforce. MFA
		// is on either way; a client that gets no codes asks for them.
		codes, gerr := h.mfaService.GenerateRecoveryCodes(r.Context(), userID)
		if gerr != nil {
			logger.Warnf("mfa: first recovery codes for user %d: %v", userID, gerr)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, dto.MFARecoveryCodesResponse{RecoveryCodes: codes})
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
// New codes are a second factor: under MFA_RECOVERY_CODES_REVERIFY_MODE=enforce
// the caller re-proves the account first, as for Disable (body
// {"password","code"}), so a bearer token alone does not yield them.
func (h *MFAHandler) RecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.recoveryCodesReverified(w, r, userID) {
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

// recoveryCodesReverified applies MFA_RECOVERY_CODES_REVERIFY_MODE and reports
// whether to go on and replace the codes; when it does not, the answer is
// written. Off: always. Observe: always, after auditing whether the request
// carried a password and a code. Enforce: only once they are checked (a
// missing code is 400, a failed check is answered as on Disable).
func (h *MFAHandler) recoveryCodesReverified(w http.ResponseWriter, r *http.Request, userID uint) bool {
	mode := h.recoveryReverifyMode
	if mode != "observe" && mode != "enforce" {
		return true
	}
	// The body is optional outside enforce (clients that send none keep
	// working under observe); an unreadable one counts as carrying nothing.
	var req dto.MFARecoveryCodesRequest
	decodeErr := json.NewDecoder(r.Body).Decode(&req)
	present := decodeErr == nil && req.Code != ""
	audit := func(outcome string, ok bool) {
		if h.recoveryReverifyAudit == nil {
			return
		}
		if err := h.recoveryReverifyAudit.LogFromRequest(r.Context(), r, service.SecurityEvent{
			UserID:    &userID,
			EventType: model.SecurityEventMFARecoveryCodesReverify,
			Success:   ok,
			Details:   map[string]interface{}{"mode": mode, "outcome": outcome},
		}); err != nil {
			logger.Warnf("mfa: could not record %s for user %d: %v", model.SecurityEventMFARecoveryCodesReverify, userID, err)
		}
	}
	if mode == "observe" {
		if present {
			audit("credentials_present", true)
		} else {
			audit("would_refuse_missing", true)
		}
		return true
	}
	if !present {
		audit("refused_missing", false)
		writeError(w, "password and code are required", http.StatusBadRequest)
		return false
	}
	if !h.reverify(r.Context(), w, userID, &req.Password, req.Code, "replace recovery codes") {
		audit("refused_failed", false)
		return false
	}
	audit("verified", true)
	return true
}

// reverify re-proves the account with the reverifier (password when the
// account has one, then a TOTP or recovery code, each failure counting toward
// the lockout) and reports whether it succeeded; when it did not, the answer
// is written: 409 without MFA, 403 for a locked account, 401 for a wrong
// factor (the same for both, so the answer does not say which), 500 when no
// reverifier is wired (fail closed) or the check could not be made.
func (h *MFAHandler) reverify(ctx context.Context, w http.ResponseWriter, userID uint, password *string, code, action string) bool {
	if h.reverifier == nil {
		logger.Warnf("mfa: %s for user %d: no re-verifier wired, refusing", action, userID)
		writeError(w, "could not "+action, http.StatusInternalServerError)
		return false
	}
	switch err := h.reverifier.ReverifyForMFAChange(ctx, userID, password, code); {
	case err == nil:
		return true
	case errors.Is(err, service.ErrMFANotEnrolled):
		writeError(w, "MFA is not enabled", http.StatusConflict)
	case errors.Is(err, service.ErrAccountLocked):
		writeError(w, "account is locked", http.StatusForbidden)
	case errors.Is(err, service.ErrInvalidCredentials), errors.Is(err, service.ErrMFAInvalidCode),
		errors.Is(err, service.ErrMFARequired), errors.Is(err, service.ErrUserNotFound):
		writeError(w, "re-authentication failed", http.StatusUnauthorized)
	default:
		logger.Warnf("mfa: re-verify to %s for user %d: %v", action, userID, err)
		writeError(w, "could not "+action, http.StatusInternalServerError)
	}
	return false
}

// Disable handles POST /api/profile/mfa/disable.
//
// P3-9: a bearer token alone (which may have been minted long ago, or stolen)
// must not be enough to strip the second factor. The caller re-proves the
// account: the current password when the account has one, plus a valid TOTP
// code or an unused recovery code. A wrong password and a wrong code get the
// same 401, so the response does not reveal which factor was wrong; each counts
// toward the account lockout, and a locked account gets 403.
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

	// The password (accounts created through invite or magic-link flows may
	// have none) and a TOTP or recovery code; each failure counts toward the
	// account lockout, so a bearer token is not a way to guess them.
	if !h.reverify(r.Context(), w, userID, &req.Password, req.Code, "disable MFA") {
		return
	}

	if err := h.mfaService.Disable(r.Context(), userID); err != nil {
		logger.Warnf("mfa: disable for user %d: %v", userID, err)
		writeError(w, "could not disable MFA", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
