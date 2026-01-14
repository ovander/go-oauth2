package web

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/socrate-auth/go-oauth/internal/repository"
	"github.com/socrate-auth/go-oauth/internal/service"
	"github.com/socrate-auth/go-oauth/internal/shared/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

// WebHandler handles web page rendering for auth flows
// These are standalone pages for email verification, password reset, and invitation acceptance
// The main OAuth2 login flow is handled separately
type WebHandler struct {
	templates    *template.Template
	authService  service.AuthService
	userService  service.UserService
	appRepo      repository.AppRepository
	emailService service.EmailService
	tokenService *auth.TokenService
	baseURL      string
}

// NewWebHandler creates a new web handler
func NewWebHandler(
	authService service.AuthService,
	userService service.UserService,
	appRepo repository.AppRepository,
	emailService service.EmailService,
	tokenService *auth.TokenService,
	baseURL string,
) (*WebHandler, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	return &WebHandler{
		templates:    tmpl,
		authService:  authService,
		userService:  userService,
		appRepo:      appRepo,
		emailService: emailService,
		tokenService: tokenService,
		baseURL:      baseURL,
	}, nil
}

// ==========================================
// Forgot Password Flow
// ==========================================

// ForgotPasswordPage renders the forgot password page
func (h *WebHandler) ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Forgot Password",
	}
	h.render(w, "forgot_password.html", data)
}

// ForgotPasswordSubmit handles forgot password form submission
func (h *WebHandler) ForgotPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, "forgot_password.html", map[string]interface{}{
			"Title": "Forgot Password",
			"Error": "Invalid form data",
		})
		return
	}

	email := r.FormValue("email")

	// Request password reset (don't reveal if email exists)
	token, _ := h.authService.RequestPasswordReset(r.Context(), email)

	// If token was generated, send email
	if token != "" {
		resetURL := h.baseURL + "/auth/reset-password?token=" + token
		// Get user name for email
		user, _ := h.userService.GetByEmail(r.Context(), email)
		name := email
		if user != nil {
			name = user.Name
		}
		h.emailService.SendPasswordResetEmail(email, name, resetURL)
	}

	data := map[string]interface{}{
		"Title":   "Forgot Password",
		"Success": true,
	}
	h.render(w, "forgot_password.html", data)
}

// ==========================================
// Reset Password Flow
// ==========================================

// ResetPasswordPage renders the reset password page
func (h *WebHandler) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	// Validate token
	_, err := h.tokenService.VerifyEmailToken(token)
	if err != nil {
		data := map[string]interface{}{
			"Title":      "Reset Password",
			"TokenError": true,
		}
		h.render(w, "reset_password.html", data)
		return
	}

	data := map[string]interface{}{
		"Title": "Reset Password",
		"Token": token,
	}
	h.render(w, "reset_password.html", data)
}

// ResetPasswordSubmit handles reset password form submission
func (h *WebHandler) ResetPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, "reset_password.html", map[string]interface{}{
			"Title": "Reset Password",
			"Error": "Invalid form data",
		})
		return
	}

	token := r.FormValue("token")
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")

	if password != passwordConfirm {
		data := map[string]interface{}{
			"Title": "Reset Password",
			"Token": token,
			"Error": "Passwords do not match",
		}
		h.render(w, "reset_password.html", data)
		return
	}

	if len(password) < 8 {
		data := map[string]interface{}{
			"Title": "Reset Password",
			"Token": token,
			"Error": "Password must be at least 8 characters",
		}
		h.render(w, "reset_password.html", data)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), token, password); err != nil {
		data := map[string]interface{}{
			"Title":      "Reset Password",
			"TokenError": true,
		}
		h.render(w, "reset_password.html", data)
		return
	}

	data := map[string]interface{}{
		"Title":   "Reset Password",
		"Success": true,
	}
	h.render(w, "reset_password.html", data)
}

// ==========================================
// Email Verification Flow
// ==========================================

// VerifyEmailPage handles email verification
func (h *WebHandler) VerifyEmailPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	err := h.authService.VerifyEmail(r.Context(), token)
	if err != nil {
		data := map[string]interface{}{
			"Title": "Email Verification",
			"Error": "This verification link is invalid or has expired.",
		}
		h.render(w, "verify_email.html", data)
		return
	}

	data := map[string]interface{}{
		"Title":   "Email Verification",
		"Success": true,
	}
	h.render(w, "verify_email.html", data)
}

// ==========================================
// Invitation Accept Flow
// ==========================================

// AcceptInvitePage renders the accept invitation page
func (h *WebHandler) AcceptInvitePage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	// Validate invite token
	claims, err := h.tokenService.VerifyInviteToken(token)
	if err != nil {
		data := map[string]interface{}{
			"Title":      "Accept Invitation",
			"TokenError": true,
		}
		h.render(w, "accept_invite.html", data)
		return
	}

	// Get app name
	appName := "the application"
	if app, err := h.appRepo.FindByID(r.Context(), claims.AppID); err == nil {
		appName = app.Name
	}

	data := map[string]interface{}{
		"Title":   "Accept Invitation",
		"Token":   token,
		"Email":   claims.Email,
		"AppName": appName,
	}
	h.render(w, "accept_invite.html", data)
}

// AcceptInviteSubmit handles accept invitation form submission
func (h *WebHandler) AcceptInviteSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, "accept_invite.html", map[string]interface{}{
			"Title": "Accept Invitation",
			"Error": "Invalid form data",
		})
		return
	}

	token := r.FormValue("token")
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")

	// Validate invite token first
	claims, err := h.tokenService.VerifyInviteToken(token)
	if err != nil {
		data := map[string]interface{}{
			"Title":      "Accept Invitation",
			"TokenError": true,
		}
		h.render(w, "accept_invite.html", data)
		return
	}

	// Get app name
	appName := "the application"
	if app, err := h.appRepo.FindByID(r.Context(), claims.AppID); err == nil {
		appName = app.Name
	}

	if password != passwordConfirm {
		data := map[string]interface{}{
			"Title":   "Accept Invitation",
			"Token":   token,
			"Email":   claims.Email,
			"AppName": appName,
			"Error":   "Passwords do not match",
		}
		h.render(w, "accept_invite.html", data)
		return
	}

	if len(password) < 8 {
		data := map[string]interface{}{
			"Title":   "Accept Invitation",
			"Token":   token,
			"Email":   claims.Email,
			"AppName": appName,
			"Error":   "Password must be at least 8 characters",
		}
		h.render(w, "accept_invite.html", data)
		return
	}

	// Accept the invitation
	_, err = h.authService.AcceptInvite(r.Context(), token, password)
	if err != nil {
		data := map[string]interface{}{
			"Title":   "Accept Invitation",
			"Token":   token,
			"Email":   claims.Email,
			"AppName": appName,
			"Error":   err.Error(),
		}
		h.render(w, "accept_invite.html", data)
		return
	}

	data := map[string]interface{}{
		"Title":   "Accept Invitation",
		"Success": true,
		"AppName": appName,
	}
	h.render(w, "accept_invite.html", data)
}

// ==========================================
// Template Rendering
// ==========================================

func (h *WebHandler) render(w http.ResponseWriter, name string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Execute the specific template which uses base
	if err := h.templates.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}
