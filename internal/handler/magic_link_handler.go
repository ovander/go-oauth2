package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/service"
)

// MagicLinkHandler handles passwordless magic-link authentication endpoints.
type MagicLinkHandler struct {
	magicLinkService service.MagicLinkService
	environment      string
}

// NewMagicLinkHandler creates a new MagicLinkHandler.
func NewMagicLinkHandler(magicLinkService service.MagicLinkService, environment string) *MagicLinkHandler {
	return &MagicLinkHandler{
		magicLinkService: magicLinkService,
		environment:      environment,
	}
}

// Request handles POST /api/apps/{app_id}/service/magic-link.
//
// This endpoint is service-account (M2M) protected — only the authenticated
// app backend can trigger magic-link emails on behalf of its users.
// ServiceAccountMiddleware has already validated the client_credentials token
// and injected the *model.App into the request context; this handler just
// reads the target email from the JSON body.
//
// The response is always the same opaque message regardless of whether the
// email is registered in this app — this prevents user enumeration via the
// backend-to-backend channel.
func (h *MagicLinkHandler) Request(w http.ResponseWriter, r *http.Request) {
	// The app identity is established by ServiceAccountMiddleware.
	app, ok := middleware.GetServiceAccountAppFromContext(r.Context())
	if !ok {
		// Should never happen — the route is behind ServiceAccountMiddleware —
		// but fail closed rather than silently.
		writeError(w, "service account context missing", http.StatusInternalServerError)
		return
	}

	var req dto.MagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		writeError(w, "email is required", http.StatusBadRequest)
		return
	}

	rawToken, err := h.magicLinkService.RequestMagicLink(r.Context(), req.Email, app)
	if err != nil {
		if errors.Is(err, service.ErrMagicLinkRateLimited) {
			writeError(w, "too many requests, please try again later", http.StatusTooManyRequests)
			return
		}
		// App-level configuration error, independent of the address: say so
		// rather than accept a request whose email would open no page.
		if errors.Is(err, service.ErrMagicLinkNotConfigured) {
			writeError(w, err.Error(), http.StatusConflict)
			return
		}
		// Any other internal error: return opaque success to avoid leaking info.
		// The error is logged inside the service layer.
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, dto.MagicLinkResponse{
			Message: "If that email address is registered, a login link has been sent.",
		})
		return
	}

	resp := dto.MagicLinkResponse{
		Message: "If that email address is registered, a login link has been sent.",
	}

	// Only expose the raw URL in development mode so that integration tests
	// can exercise the full flow without a real mail server.
	if (h.environment == "development" || h.environment == "dev") && rawToken != "" {
		resp.MagicURL = rawToken // callers must prepend the base URL themselves if needed
	}

	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, resp)
}

// Verify handles POST /api/auth/magic-link/verify.
//
// The caller submits the raw token (received via email) plus the client_id.
// On success, a full token set (access, refresh, ID) is returned — identical
// to the Login response — so that clients need no special magic-link code path.
//
// The endpoint is intentionally POST-only.  Email clients and security scanners
// frequently follow links via GET to generate previews; accepting GET here would
// silently consume the single-use token before the user clicks.
func (h *MagicLinkHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.MagicLinkVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Token == "" || req.ClientID == "" {
		writeError(w, "token and client_id are required", http.StatusBadRequest)
		return
	}

	resp, err := h.magicLinkService.VerifyMagicLink(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTokenAlreadyUsed):
			writeError(w, "this login link has already been used", http.StatusUnprocessableEntity)
		case errors.Is(err, service.ErrAccountLocked):
			writeError(w, "account is locked, please try again later", http.StatusForbidden)
		default:
			// Covers expired, not-found, app-mismatch — all map to 401 to
			// prevent distinguishing between wrong and used/expired tokens.
			writeError(w, "invalid or expired login link", http.StatusUnauthorized)
		}
		return
	}

	writeJSON(w, resp)
}
