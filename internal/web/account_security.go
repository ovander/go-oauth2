package web

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// accountSessionAudience is the client id a page session is issued for. Page
// sessions reuse the signed consent token (10 minutes, HMAC with
// SECRET_KEY_BASE); a consent token for a real client never carries this id
// (client ids are generated), and the consent POST checks the client id, so
// one cannot stand in for the other.
const accountSessionAudience = "socrate:account-security"

// AccountSecurityHandler serves Socrate's hosted account page
// (ACCOUNT_SECURITY_PAGE): a user who is not a Socrate admin signs in with
// their own credentials and turns two-factor authentication on, regenerates
// recovery codes, or turns it off. It is for the users of the applications,
// which have no MFA screen of their own; Socrate admins use the admin console.
//
//	GET  /account/security   the sign-in form
//	POST /account/security   one action per post (field "action"):
//	                         signin, overview, enroll, confirm, recovery_codes,
//	                         disable, signout
//
// There is no server-side session. Signing in yields a signed page session
// (10 minutes) carried in a hidden field; every post also carries the
// double-submit CSRF token. Every page is no-store.
type AccountSecurityHandler struct {
	tmpl   *template.Template
	auth   service.AuthService
	mfa    service.MFAService
	secret []byte
	secure bool
}

// NewAccountSecurityHandler builds the handler. secret is SECRET_KEY_BASE and
// must not be empty (the page session could not be verified); issuer decides
// whether the CSRF cookie is Secure.
func NewAccountSecurityHandler(authService service.AuthService, mfaService service.MFAService, secret []byte, issuer string) (*AccountSecurityHandler, error) {
	if authService == nil || mfaService == nil {
		return nil, errors.New("account security page: auth and MFA services are required")
	}
	if len(secret) == 0 {
		return nil, errors.New("account security page: SECRET_KEY_BASE is required")
	}
	base, err := templateFS.ReadFile("templates/base.html")
	if err != nil {
		return nil, err
	}
	content, err := templateFS.ReadFile("templates/account_security.html")
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("base").Parse(string(base))
	if err != nil {
		return nil, err
	}
	if _, err := tmpl.Parse(string(content)); err != nil {
		return nil, err
	}
	return &AccountSecurityHandler{
		tmpl:   tmpl,
		auth:   authService,
		mfa:    mfaService,
		secret: secret,
		secure: strings.HasPrefix(issuer, "https://"),
	}, nil
}

// Page handles GET /account/security: the sign-in form.
func (h *AccountSecurityHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderSignIn(w, "", "", false, "")
}

// Submit handles POST /account/security.
func (h *AccountSecurityHandler) Submit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		h.renderSignIn(w, "", "Invalid form data.", false, "")
		return
	}
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		h.renderSignIn(w, "", "This page expired. Sign in again.", false, "")
		return
	}

	action := r.PostFormValue("action")
	switch action {
	case "signin":
		h.signIn(w, r)
		return
	case "signout":
		h.renderSignIn(w, "", "", false, "You are signed out.")
		return
	}

	userID, err := h.sessionUser(r.PostFormValue("session"))
	if err != nil {
		h.renderSignIn(w, "", "Your session ended. Sign in again.", false, "")
		return
	}
	session := r.PostFormValue("session")

	switch action {
	case "overview":
		h.renderOverview(w, r, userID, session, "", "")
	case "enroll":
		h.enroll(w, r, userID, session)
	case "confirm":
		h.confirm(w, r, userID, session)
	case "recovery_codes":
		h.recoveryCodes(w, r, userID, session)
	case "disable":
		h.disable(w, r, userID, session)
	default:
		h.renderOverview(w, r, userID, session, "Unknown action.", "")
	}
}

func (h *AccountSecurityHandler) signIn(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("email"))
	user, err := h.auth.AuthenticateAccount(r.Context(), email, r.PostFormValue("password"), strings.TrimSpace(r.PostFormValue("mfa_code")))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFARequired):
			h.renderSignIn(w, email, "Enter your password again with the code from your authenticator app.", true, "")
		case errors.Is(err, service.ErrMFAInvalidCode):
			h.renderSignIn(w, email, "Invalid email, password or authentication code.", true, "")
		case errors.Is(err, service.ErrAccountLocked):
			h.renderSignIn(w, email, "Your account is locked. Try again later.", false, "")
		case errors.Is(err, service.ErrUserNotVerified):
			h.renderSignIn(w, email, "Verify your email address first.", false, "")
		case errors.Is(err, service.ErrAccountPageAdmin):
			h.renderSignIn(w, "", "Socrate administrators manage two-factor authentication in the admin console (My Profile).", false, "")
		case errors.Is(err, service.ErrInvalidCredentials):
			h.renderSignIn(w, email, "Invalid email, password or authentication code.", false, "")
		default:
			logger.Warnf("account security: sign-in failed: %v", err)
			h.renderSignIn(w, email, "Sign-in failed. Please try again.", false, "")
		}
		return
	}
	session, err := auth.IssueConsentToken(user.ID, accountSessionAudience, h.secret)
	if err != nil {
		logger.Warnf("account security: issue page session: %v", err)
		h.renderSignIn(w, email, "Sign-in failed. Please try again.", false, "")
		return
	}
	h.renderOverview(w, r, user.ID, session, "", "")
}

// sessionUser verifies a page session and returns its user.
func (h *AccountSecurityHandler) sessionUser(session string) (uint, error) {
	userID, audience, err := auth.ValidateConsentToken(session, h.secret)
	if err != nil {
		return 0, err
	}
	if audience != accountSessionAudience || userID == 0 {
		return 0, auth.ErrConsentTokenInvalid
	}
	return userID, nil
}

func (h *AccountSecurityHandler) enroll(w http.ResponseWriter, r *http.Request, userID uint, session string) {
	secret, uri, err := h.mfa.BeginEnrollment(r.Context(), userID)
	if err != nil {
		if errors.Is(err, service.ErrMFAAlreadyEnabled) {
			h.renderOverview(w, r, userID, session, "Two-factor authentication is already on.", "")
			return
		}
		logger.Warnf("account security: begin enrollment for user %d: %v", userID, err)
		h.renderOverview(w, r, userID, session, "Could not start the setup. Please try again.", "")
		return
	}
	h.render(w, map[string]interface{}{
		"View":    "enroll",
		"Session": session,
		"Secret":  groupSecret(secret),
		"OTPAuth": otpauthURL(uri),
	})
}

func (h *AccountSecurityHandler) confirm(w http.ResponseWriter, r *http.Request, userID uint, session string) {
	err := h.mfa.ConfirmEnrollment(r.Context(), userID, strings.TrimSpace(r.PostFormValue("code")))
	switch {
	case err == nil:
	case errors.Is(err, service.ErrMFAInvalidCode):
		h.render(w, map[string]interface{}{
			"View":    "enroll",
			"Session": session,
			"Error":   "Code not accepted. Check that your device's clock is right, or start again with a new key.",
		})
		return
	case errors.Is(err, service.ErrMFANotEnrolled):
		h.renderOverview(w, r, userID, session, "Start the setup first.", "")
		return
	default:
		logger.Warnf("account security: confirm enrollment for user %d: %v", userID, err)
		h.renderOverview(w, r, userID, session, "Could not turn on two-factor authentication. Please try again.", "")
		return
	}
	// Hand out recovery codes at once: without them a lost phone locks the account.
	codes, err := h.mfa.GenerateRecoveryCodes(r.Context(), userID)
	if err != nil {
		logger.Warnf("account security: recovery codes for user %d: %v", userID, err)
		h.renderOverview(w, r, userID, session, "", "Two-factor authentication is on. Generate recovery codes now.")
		return
	}
	h.render(w, map[string]interface{}{
		"View":    "codes",
		"Session": session,
		"Codes":   codes,
		"Notice":  "Two-factor authentication is on.",
	})
}

func (h *AccountSecurityHandler) recoveryCodes(w http.ResponseWriter, r *http.Request, userID uint, session string) {
	codes, err := h.mfa.GenerateRecoveryCodes(r.Context(), userID)
	if err != nil {
		if errors.Is(err, service.ErrMFANotEnrolled) {
			h.renderOverview(w, r, userID, session, "Turn on two-factor authentication first.", "")
			return
		}
		logger.Warnf("account security: recovery codes for user %d: %v", userID, err)
		h.renderOverview(w, r, userID, session, "Could not generate recovery codes. Please try again.", "")
		return
	}
	h.render(w, map[string]interface{}{
		"View":    "codes",
		"Session": session,
		"Codes":   codes,
		"Notice":  "Your previous recovery codes no longer work.",
	})
}

// disable needs a fresh code on top of the page session, like the API's
// re-authentication (P3-9): a TOTP code or an unused recovery code.
func (h *AccountSecurityHandler) disable(w http.ResponseWriter, r *http.Request, userID uint, session string) {
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" {
		h.renderOverview(w, r, userID, session, "Enter a current code or a recovery code.", "")
		return
	}
	switch err := h.mfa.Verify(r.Context(), userID, code); {
	case err == nil:
	case errors.Is(err, service.ErrMFANotEnrolled):
		h.renderOverview(w, r, userID, session, "Two-factor authentication is already off.", "")
		return
	case errors.Is(err, service.ErrMFAInvalidCode):
		redeemed, rerr := h.mfa.RedeemRecoveryCode(r.Context(), userID, code)
		if rerr != nil {
			logger.Warnf("account security: redeem recovery code for user %d: %v", userID, rerr)
			h.renderOverview(w, r, userID, session, "Could not turn off two-factor authentication. Please try again.", "")
			return
		}
		if !redeemed {
			h.renderOverview(w, r, userID, session, "Code not accepted.", "")
			return
		}
	default:
		logger.Warnf("account security: verify before disable for user %d: %v", userID, err)
		h.renderOverview(w, r, userID, session, "Could not turn off two-factor authentication. Please try again.", "")
		return
	}
	if err := h.mfa.Disable(r.Context(), userID); err != nil {
		logger.Warnf("account security: disable for user %d: %v", userID, err)
		h.renderOverview(w, r, userID, session, "Could not turn off two-factor authentication. Please try again.", "")
		return
	}
	h.renderOverview(w, r, userID, session, "", "Two-factor authentication is off.")
}

func (h *AccountSecurityHandler) renderOverview(w http.ResponseWriter, r *http.Request, userID uint, session, errMsg, notice string) {
	enabled, err := h.mfa.IsEnabled(r.Context(), userID)
	if err != nil {
		logger.Warnf("account security: MFA status for user %d: %v", userID, err)
		h.renderSignIn(w, "", "Could not read your account. Please try again.", false, "")
		return
	}
	remaining := 0
	if enabled {
		if remaining, err = h.mfa.RemainingRecoveryCodes(r.Context(), userID); err != nil {
			logger.Warnf("account security: recovery-code count for user %d: %v", userID, err)
		}
	}
	h.render(w, map[string]interface{}{
		"View":      "overview",
		"Session":   session,
		"Enabled":   enabled,
		"Remaining": remaining,
		"Error":     errMsg,
		"Notice":    notice,
	})
}

func (h *AccountSecurityHandler) renderSignIn(w http.ResponseWriter, email, errMsg string, showMFA bool, notice string) {
	h.render(w, map[string]interface{}{
		"View":    "signin",
		"Email":   email,
		"Error":   errMsg,
		"Notice":  notice,
		"ShowMFA": showMFA,
	})
}

// render writes a page with a fresh CSRF token. Pages can show a TOTP key or
// recovery codes, so none may be cached or leak a referrer.
func (h *AccountSecurityHandler) render(w http.ResponseWriter, data map[string]interface{}) {
	csrf, err := auth.GenerateCSRFToken(w, h.secure)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	data["CSRF"] = csrf
	data["Title"] = "Account security"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := h.tmpl.ExecuteTemplate(w, "base", data); err != nil {
		logger.Warnf("account security: render: %v", err)
	}
}

// groupSecret shows the key in groups of four, as authenticator apps do.
func groupSecret(secret string) string {
	var b strings.Builder
	for i, c := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// otpauthURL marks the provisioning URI safe for an href. html/template
// refuses non-http(s) schemes, so only an otpauth:// URI is ever passed through.
func otpauthURL(uri string) template.URL {
	if !strings.HasPrefix(uri, "otpauth://") {
		return ""
	}
	return template.URL(uri) // #nosec G203 -- scheme checked above; the URI is built by the MFA service
}
