package web

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"

	"github.com/socrate-auth/go-oauth/internal/dto"
	"github.com/socrate-auth/go-oauth/internal/repository"
	"github.com/socrate-auth/go-oauth/internal/service"
	"github.com/socrate-auth/go-oauth/internal/shared/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

// WebHandler handles web page rendering for auth flows
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

// LoginPage renders the login page
func (h *WebHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":               "Sign In",
		"ClientID":            r.URL.Query().Get("client_id"),
		"RedirectURI":         r.URL.Query().Get("redirect_uri"),
		"State":               r.URL.Query().Get("state"),
		"Scope":               r.URL.Query().Get("scope"),
		"ResponseType":        r.URL.Query().Get("response_type"),
		"Nonce":               r.URL.Query().Get("nonce"),
		"CodeChallenge":       r.URL.Query().Get("code_challenge"),
		"CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
		"AllowSignup":         true,
	}

	h.render(w, "login.html", data)
}

// LoginSubmit handles login form submission
func (h *WebHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderLoginError(w, r, "Invalid form data")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")

	// Authenticate user
	loginReq := dto.LoginRequest{
		Email:       email,
		Password:    password,
		AppClientID: clientID,
	}
	loginResp, err := h.authService.Login(r.Context(), loginReq)
	if err != nil {
		h.renderLoginError(w, r, "Invalid email or password")
		return
	}

	// If no redirect URI, just show success
	if redirectURI == "" || clientID == "" {
		http.Redirect(w, r, "/auth/login?success=1", http.StatusSeeOther)
		return
	}

	// Build redirect URL with authorization code
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.renderLoginError(w, r, "Invalid redirect URI")
		return
	}

	q := redirectURL.Query()
	if state != "" {
		q.Set("state", state)
	}
	// For now, redirect with the tokens directly (implicit flow style)
	// In production, you'd generate an auth code here
	q.Set("access_token", loginResp.AccessToken)
	q.Set("token_type", "Bearer")
	redirectURL.Fragment = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
}

func (h *WebHandler) renderLoginError(w http.ResponseWriter, r *http.Request, errMsg string) {
	data := map[string]interface{}{
		"Title":               "Sign In",
		"Error":               errMsg,
		"Email":               r.FormValue("email"),
		"ClientID":            r.FormValue("client_id"),
		"RedirectURI":         r.FormValue("redirect_uri"),
		"State":               r.FormValue("state"),
		"Scope":               r.FormValue("scope"),
		"ResponseType":        r.FormValue("response_type"),
		"Nonce":               r.FormValue("nonce"),
		"CodeChallenge":       r.FormValue("code_challenge"),
		"CodeChallengeMethod": r.FormValue("code_challenge_method"),
		"AllowSignup":         true,
	}
	h.render(w, "login.html", data)
}

// SignupPage renders the signup page
func (h *WebHandler) SignupPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":       "Sign Up",
		"ClientID":    r.URL.Query().Get("client_id"),
		"RedirectURI": r.URL.Query().Get("redirect_uri"),
	}
	h.render(w, "signup.html", data)
}

// SignupSubmit handles signup form submission
func (h *WebHandler) SignupSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderSignupError(w, r, "Invalid form data")
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")

	// Create user
	signupReq := dto.SignupRequest{
		Name:     name,
		Email:    email,
		Password: password,
		ClientID: clientID,
	}
	user, verifyToken, err := h.authService.Signup(r.Context(), signupReq)
	if err != nil {
		h.renderSignupError(w, r, err.Error())
		return
	}

	// Send verification email
	verifyURL := h.baseURL + "/auth/verify-email?token=" + verifyToken
	if err := h.emailService.SendVerificationEmail(email, user.Name, verifyURL); err != nil {
		// Log error but don't fail - user is created
	}

	data := map[string]interface{}{
		"Title":    "Sign Up",
		"Success":  true,
		"Email":    email,
		"ClientID": clientID,
	}
	h.render(w, "signup.html", data)
}

func (h *WebHandler) renderSignupError(w http.ResponseWriter, r *http.Request, errMsg string) {
	data := map[string]interface{}{
		"Title":       "Sign Up",
		"Error":       errMsg,
		"Name":        r.FormValue("name"),
		"Email":       r.FormValue("email"),
		"ClientID":    r.FormValue("client_id"),
		"RedirectURI": r.FormValue("redirect_uri"),
	}
	h.render(w, "signup.html", data)
}

// ForgotPasswordPage renders the forgot password page
func (h *WebHandler) ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":    "Forgot Password",
		"ClientID": r.URL.Query().Get("client_id"),
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
	clientID := r.FormValue("client_id")

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
		"Title":    "Forgot Password",
		"Success":  true,
		"ClientID": clientID,
	}
	h.render(w, "forgot_password.html", data)
}

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

func (h *WebHandler) render(w http.ResponseWriter, name string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// First execute base template
	if err := h.templates.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}
