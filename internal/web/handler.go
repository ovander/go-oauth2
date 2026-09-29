package web

import (
	"embed"
	"errors"
	"html/template"
	"net/http"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/logger"
)

//go:embed templates/*.html
var templateFS embed.FS

// WebHandler handles web page rendering for auth flows
type WebHandler struct {
	templates    map[string]*template.Template
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
	// Read base template
	baseContent, err := templateFS.ReadFile("templates/base.html")
	if err != nil {
		return nil, err
	}

	// Template files to load
	templateFiles := []string{
		"login.html",
		"signup.html",
		"forgot_password.html",
		"reset_password.html",
		"verify_email.html",
		"accept_invite.html",
	}

	templates := make(map[string]*template.Template)
	for _, name := range templateFiles {
		content, err := templateFS.ReadFile("templates/" + name)
		if err != nil {
			return nil, err
		}

		// Parse base + content template together
		tmpl, err := template.New("base").Parse(string(baseContent))
		if err != nil {
			return nil, err
		}
		_, err = tmpl.Parse(string(content))
		if err != nil {
			return nil, err
		}
		templates[name] = tmpl
	}

	return &WebHandler{
		templates:    templates,
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
	clientID := r.URL.Query().Get("client_id")

	data := map[string]interface{}{
		"Title":    "Forgot Password",
		"ClientID": clientID,
	}

	// Get app name if client_id provided
	if clientID != "" {
		if app, err := h.appRepo.FindByClientID(r.Context(), clientID); err == nil {
			data["AppName"] = app.Name
		}
	}

	h.render(w, "forgot_password.html", data)
}

// ForgotPasswordSubmit handles forgot password form submission
func (h *WebHandler) ForgotPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	// G120: cap the form body to prevent memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.render(w, "forgot_password.html", map[string]interface{}{
			"Title": "Forgot Password",
			"Error": "Invalid form data",
		})
		return
	}

	email := r.FormValue("email")
	clientID := r.FormValue("client_id")

	// Build app context if client_id provided
	var appCtx *auth.AppContext
	var appName string
	if clientID != "" {
		if app, err := h.appRepo.FindByClientID(r.Context(), clientID); err == nil {
			appName = app.Name
			appCtx = &auth.AppContext{
				AppID:   app.ID,
				AppName: app.Name,
			}
			if len(app.RedirectURIs) > 0 {
				appCtx.RedirectURI = app.RedirectURIs[0]
			}
		}
	}

	// Request password reset with app context
	token, _ := h.authService.RequestPasswordReset(r.Context(), email, appCtx)

	// If token was generated, send email with app name
	if token != "" {
		resetURL := h.baseURL + "/auth/reset-password?token=" + token
		// Get user name for email
		user, _ := h.userService.GetByEmail(r.Context(), email)
		name := email
		if user != nil {
			name = user.Name
		}
		if err := h.emailService.SendPasswordResetEmail(email, name, appName, resetURL); err != nil {
			logger.Warnf("ForgotPasswordSubmit: failed to send password reset email to %s: %v", email, err)
		}
	}

	data := map[string]interface{}{
		"Title":    "Forgot Password",
		"ClientID": clientID,
		"AppName":  appName,
		"Success":  true,
	}
	h.render(w, "forgot_password.html", data)
}

// ==========================================
// Reset Password Flow
// ==========================================

// ResetPasswordPage renders the reset password page
func (h *WebHandler) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	// Validate token and extract app context
	claims, err := h.tokenService.VerifyEmailToken(token)
	if err != nil {
		data := map[string]interface{}{
			"Title":      "Reset Password",
			"TokenError": true,
		}
		h.render(w, "reset_password.html", data)
		return
	}

	// Get app name from token claims
	appName := claims.AppName
	if appName == "" {
		appName = "Socrate"
	}

	data := map[string]interface{}{
		"Title":   "Reset Password",
		"AppName": appName,
		"Token":   token,
	}
	h.render(w, "reset_password.html", data)
}

// ResetPasswordSubmit handles reset password form submission
func (h *WebHandler) ResetPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // G120
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

	// Parse token to get app context (for display purposes)
	claims, _ := h.tokenService.VerifyEmailToken(token)
	var appName, redirectURI string
	if claims != nil {
		appName = claims.AppName
		redirectURI = claims.RedirectURI
	}
	if appName == "" {
		appName = "Socrate"
	}

	if password != passwordConfirm {
		data := map[string]interface{}{
			"Title":   "Reset Password",
			"AppName": appName,
			"Token":   token,
			"Error":   "Passwords do not match",
		}
		h.render(w, "reset_password.html", data)
		return
	}

	if len(password) < 8 {
		data := map[string]interface{}{
			"Title":   "Reset Password",
			"AppName": appName,
			"Token":   token,
			"Error":   "Password must be at least 8 characters",
		}
		h.render(w, "reset_password.html", data)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), token, password); err != nil {
		data := map[string]interface{}{
			"Title":      "Reset Password",
			"AppName":    appName,
			"TokenError": true,
		}
		h.render(w, "reset_password.html", data)
		return
	}

	data := map[string]interface{}{
		"Title":       "Reset Password",
		"AppName":     appName,
		"RedirectURI": redirectURI,
		"Success":     true,
	}
	h.render(w, "reset_password.html", data)
}

// ==========================================
// Email Verification Flow
// ==========================================

// VerifyEmailPage handles email verification
func (h *WebHandler) VerifyEmailPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	// Parse token first to get app context (for display purposes)
	claims, _ := h.tokenService.VerifyEmailToken(token)
	var appName, redirectURI string
	if claims != nil {
		appName = claims.AppName
		redirectURI = claims.RedirectURI
	}
	if appName == "" {
		appName = "Socrate"
	}

	err := h.authService.VerifyEmail(r.Context(), token)
	if err != nil {
		data := map[string]interface{}{
			"Title":   "Email Verification",
			"AppName": appName,
			"Error":   "This verification link is invalid or has expired.",
		}
		h.render(w, "verify_email.html", data)
		return
	}

	data := map[string]interface{}{
		"Title":       "Email Verification",
		"AppName":     appName,
		"RedirectURI": redirectURI,
		"Success":     true,
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // G120
	if err := r.ParseForm(); err != nil {
		h.render(w, "accept_invite.html", map[string]interface{}{
			"Title": "Accept Invitation",
			"Error": "Invalid form data",
		})
		return
	}

	token := r.FormValue("token")
	name := r.FormValue("name")
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
	_, err = h.authService.AcceptInvite(r.Context(), token, name, password)
	if err != nil {
		data := map[string]interface{}{
			"Title":   "Accept Invitation",
			"Token":   token,
			"Email":   claims.Email,
			"AppName": appName,
			"Error":   safeFormError(err, "Unable to accept the invitation. Please try again or request a new invite."),
		}
		h.render(w, "accept_invite.html", data)
		return
	}

	// Determine redirect URL from the specific app in the invite token.
	// This is safe even when a user belongs to multiple apps — the invite token
	// is scoped to exactly one app (claims.AppID), so we always redirect to the
	// right one.
	var appURL string
	if app, appErr := h.appRepo.FindByID(r.Context(), claims.AppID); appErr == nil && app.URL != nil && *app.URL != "" {
		appURL = *app.URL
	}

	data := map[string]interface{}{
		"Title":   "Accept Invitation",
		"Success": true,
		"AppName": appName,
		"AppURL":  appURL,
	}
	h.render(w, "accept_invite.html", data)
}

// ==========================================
// Login Flow
// ==========================================

// LoginPage handles GET /auth/login.
//
// P3-6: the standalone login form (and its POST /auth/login handler) was a dead
// path — it authenticated without an app context, set an `access_token` cookie
// nothing consumed, and still counted against the victim's failed-login
// lockout. Interactive sign-in lives on the hosted /oauth/authorize page, so a
// request that carries OAuth parameters is forwarded there and everything else
// gets an informational page pointing back to the application.
func (h *WebHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != "" && q.Get("redirect_uri") != "" {
		http.Redirect(w, r, h.baseURL+"/oauth/authorize?"+q.Encode(), http.StatusFound)
		return
	}

	data := map[string]interface{}{
		"Title":    "Sign In",
		"ClientID": q.Get("client_id"),
	}
	if clientID := q.Get("client_id"); clientID != "" && h.appRepo != nil {
		if app, err := h.appRepo.FindByClientID(r.Context(), clientID); err == nil {
			data["AppName"] = app.Name
		}
	}
	h.render(w, "login.html", data)
}

// ==========================================
// Signup Flow
// ==========================================

// SignupPage renders the signup page
func (h *WebHandler) SignupPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":               "Sign Up",
		"ClientID":            r.URL.Query().Get("client_id"),
		"RedirectURI":         r.URL.Query().Get("redirect_uri"),
		"State":               r.URL.Query().Get("state"),
		"Scope":               r.URL.Query().Get("scope"),
		"ResponseType":        r.URL.Query().Get("response_type"),
		"CodeChallenge":       r.URL.Query().Get("code_challenge"),
		"CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
	}
	h.render(w, "signup.html", data)
}

// SignupSubmit handles signup form submission
func (h *WebHandler) SignupSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // G120
	if err := r.ParseForm(); err != nil {
		h.render(w, "signup.html", map[string]interface{}{
			"Title": "Sign Up",
			"Error": "Invalid form data",
		})
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")

	// Preserve form data for error display
	data := map[string]interface{}{
		"Title":               "Sign Up",
		"Name":                name,
		"Email":               email,
		"ClientID":            r.FormValue("client_id"),
		"RedirectURI":         r.FormValue("redirect_uri"),
		"State":               r.FormValue("state"),
		"Scope":               r.FormValue("scope"),
		"ResponseType":        r.FormValue("response_type"),
		"CodeChallenge":       r.FormValue("code_challenge"),
		"CodeChallengeMethod": r.FormValue("code_challenge_method"),
	}

	// Validate inputs
	if name == "" {
		data["Error"] = "Name is required"
		h.render(w, "signup.html", data)
		return
	}

	if email == "" {
		data["Error"] = "Email is required"
		h.render(w, "signup.html", data)
		return
	}

	if len(password) < 8 {
		data["Error"] = "Password must be at least 8 characters"
		h.render(w, "signup.html", data)
		return
	}

	if password != passwordConfirm {
		data["Error"] = "Passwords do not match"
		h.render(w, "signup.html", data)
		return
	}

	// Register user (email is sent by the service with proper app context)
	_, _, err := h.authService.Signup(r.Context(), dto.SignupRequest{
		Name:     name,
		Email:    email,
		Password: password,
		ClientID: r.FormValue("client_id"),
	})
	if err != nil {
		data["Error"] = safeFormError(err, "Signup failed. Please check your details and try again.")
		h.render(w, "signup.html", data)
		return
	}

	data["Success"] = true
	h.render(w, "signup.html", data)
}

// ==========================================
// Template Rendering
// ==========================================

// passwordValidationErrors are the auth.ValidatePassword sentinels; their text
// is a fixed, safe instruction ("password must be at least 12 characters")
// and may be shown verbatim. Mirrors the JSON API's M1 handling.
var passwordValidationErrors = []error{
	auth.ErrPasswordTooShort,
	auth.ErrPasswordTooLong,
	auth.ErrPasswordNoLowercase,
	auth.ErrPasswordNoUppercase,
	auth.ErrPasswordNoDigit,
	auth.ErrPasswordNoSpecial,
	auth.ErrPasswordCommon,
}

// safeFormError maps a service error to a message that can be rendered to an
// unauthenticated browser (P2-1). Known sentinels get a static message; the
// password-policy errors pass through; anything else — a wrapped GORM/driver
// error, an SMTP failure, a path — is logged server-side and replaced by
// fallback so no internal detail reaches the page.
func safeFormError(err error, fallback string) string {
	switch {
	case errors.Is(err, service.ErrEmailAlreadyExists):
		return "An account with this email already exists."
	case errors.Is(err, service.ErrAppNotFound), errors.Is(err, service.ErrAppInactive):
		return "This application is not available for signup."
	case errors.Is(err, service.ErrTokenAlreadyUsed):
		return "This invitation has already been used."
	case errors.Is(err, service.ErrInvalidToken):
		return "This invitation is invalid or has expired."
	}
	for _, sentinel := range passwordValidationErrors {
		if errors.Is(err, sentinel) {
			return err.Error()
		}
	}
	logger.Warnf("web form request failed: %v", err)
	return fallback
}

func (h *WebHandler) render(w http.ResponseWriter, name string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, ok := h.templates[name]
	if !ok {
		http.Error(w, "Template not found: "+name, http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}
