package web

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/service"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
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
// Login Flow
// ==========================================

// LoginPage renders the login page
func (h *WebHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":               "Sign In",
		"ClientID":            r.URL.Query().Get("client_id"),
		"RedirectURI":         r.URL.Query().Get("redirect_uri"),
		"State":               r.URL.Query().Get("state"),
		"Scope":               r.URL.Query().Get("scope"),
		"ResponseType":        r.URL.Query().Get("response_type"),
		"CodeChallenge":       r.URL.Query().Get("code_challenge"),
		"CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
		"Nonce":               r.URL.Query().Get("nonce"),
	}

	// Parse scopes for display
	if scope := r.URL.Query().Get("scope"); scope != "" {
		data["Scopes"] = parseScopeDescriptions(scope)
	}

	h.render(w, "login.html", data)
}

// LoginSubmit handles login form submission
func (h *WebHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, "login.html", map[string]interface{}{
			"Title": "Sign In",
			"Error": "Invalid form data",
		})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Preserve OAuth parameters for error display
	data := map[string]interface{}{
		"Title":               "Sign In",
		"Email":               email,
		"ClientID":            r.FormValue("client_id"),
		"RedirectURI":         r.FormValue("redirect_uri"),
		"State":               r.FormValue("state"),
		"Scope":               r.FormValue("scope"),
		"ResponseType":        r.FormValue("response_type"),
		"CodeChallenge":       r.FormValue("code_challenge"),
		"CodeChallengeMethod": r.FormValue("code_challenge_method"),
		"Nonce":               r.FormValue("nonce"),
	}

	// Authenticate user
	tokens, err := h.authService.Login(r.Context(), dto.LoginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		data["Error"] = "Invalid email or password"
		h.render(w, "login.html", data)
		return
	}

	// If there's a redirect_uri, redirect back to OAuth flow
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI != "" {
		// Build OAuth authorize URL with authentication
		authURL := h.baseURL + "/oauth/authorize?" +
			"client_id=" + r.FormValue("client_id") +
			"&redirect_uri=" + r.FormValue("redirect_uri") +
			"&response_type=" + r.FormValue("response_type") +
			"&scope=" + r.FormValue("scope") +
			"&state=" + r.FormValue("state")
		if cc := r.FormValue("code_challenge"); cc != "" {
			authURL += "&code_challenge=" + cc + "&code_challenge_method=" + r.FormValue("code_challenge_method")
		}
		if nonce := r.FormValue("nonce"); nonce != "" {
			authURL += "&nonce=" + nonce
		}

		// Set auth cookie and redirect
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    tokens.AccessToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}

	// No OAuth flow, just show success
	data["Success"] = true
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

	// Register user
	_, verifyToken, err := h.authService.Signup(r.Context(), dto.SignupRequest{
		Name:     name,
		Email:    email,
		Password: password,
		ClientID: r.FormValue("client_id"),
	})
	if err != nil {
		data["Error"] = err.Error()
		h.render(w, "signup.html", data)
		return
	}

	// Send verification email if token provided
	if verifyToken != "" && h.emailService != nil {
		verifyURL := h.baseURL + "/auth/verify-email?token=" + verifyToken
		h.emailService.SendVerificationEmail(email, name, verifyURL)
	}

	data["Success"] = true
	h.render(w, "signup.html", data)
}

// ==========================================
// Template Rendering
// ==========================================

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

// parseScopeDescriptions converts scope strings to human-readable descriptions
func parseScopeDescriptions(scope string) []string {
	scopes := strings.Fields(scope)
	descriptions := make([]string, 0, len(scopes))

	scopeMap := map[string]string{
		"openid":         "Verify your identity",
		"profile":        "Access your profile information",
		"email":          "Access your email address",
		"offline_access": "Maintain access when you're not using the app",
		"api":            "Access API on your behalf",
	}

	for _, s := range scopes {
		if desc, ok := scopeMap[s]; ok {
			descriptions = append(descriptions, desc)
		}
	}

	return descriptions
}
