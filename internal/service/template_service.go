package service

import (
	"bytes"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/ovander/go-oauth2/pkg/logger"
	"github.com/ovander/go-oauth2/web"
)

// TemplateService handles rendering of HTML templates
type TemplateService struct {
	loginTemplate          *template.Template
	consentTemplate        *template.Template
	errorTemplate          *template.Template
	acceptInviteTemplate   *template.Template
	forgotPasswordTemplate *template.Template
	resetPasswordTemplate  *template.Template
}

// NewTemplateService creates a new template service
func NewTemplateService() *TemplateService {
	// Parse login template with base
	loginTmpl := template.Must(template.New("login").Parse(mustReadTemplate("templates/base.html")))
	template.Must(loginTmpl.Parse(mustReadTemplate("templates/login.html")))

	// Parse consent template with base (CRIT-04)
	consentTmpl := template.Must(template.New("consent").Parse(mustReadTemplate("templates/base.html")))
	template.Must(consentTmpl.Parse(mustReadTemplate("templates/consent.html")))

	// Parse error template with base
	errorTmpl := template.Must(template.New("error").Parse(mustReadTemplate("templates/base.html")))
	template.Must(errorTmpl.Parse(mustReadTemplate("templates/error.html")))

	// Parse accept invite template with base
	acceptInviteTmpl := template.Must(template.New("accept_invite").Parse(mustReadTemplate("templates/base.html")))
	template.Must(acceptInviteTmpl.Parse(mustReadTemplate("templates/accept_invite.html")))

	// Parse forgot password template with base
	forgotPasswordTmpl := template.Must(template.New("forgot_password").Parse(mustReadTemplate("templates/base.html")))
	template.Must(forgotPasswordTmpl.Parse(mustReadTemplate("templates/forgot_password.html")))

	// Parse reset password template with base
	resetPasswordTmpl := template.Must(template.New("reset_password").Parse(mustReadTemplate("templates/base.html")))
	template.Must(resetPasswordTmpl.Parse(mustReadTemplate("templates/reset_password.html")))

	logger.WithFields(logger.Fields{
		"service":   "template",
		"templates": []string{"login", "consent", "error", "accept_invite", "forgot_password", "reset_password"},
	}).Debug("✅ Template service initialized")

	return &TemplateService{
		loginTemplate:          loginTmpl,
		consentTemplate:        consentTmpl,
		errorTemplate:          errorTmpl,
		acceptInviteTemplate:   acceptInviteTmpl,
		forgotPasswordTemplate: forgotPasswordTmpl,
		resetPasswordTemplate:  resetPasswordTmpl,
	}
}

func mustReadTemplate(path string) string {
	content, err := web.Templates.ReadFile(path)
	if err != nil {
		panic("failed to read template " + path + ": " + err.Error())
	}
	return string(content)
}

// LoginPageData contains data for the login page template
type LoginPageData struct {
	AppName             string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Email               string
	Error               string
	Scopes              []string
	// CSRFToken is embedded in the form as a hidden field and must match the
	// _csrf cookie on POST (CRIT-03 double-submit cookie pattern).
	CSRFToken string
	// MaxAge is the OIDC max_age parameter (LOW-02).  -1 means "not specified".
	// Preserved as a hidden field so POST /oauth/authorize can pass it to the
	// service's Authorize method for re-authentication enforcement.
	MaxAge int
	// ShowMFA shows the authentication-code field: set once the password was
	// accepted for a user with MFA enabled, so the form asks for the code.
	ShowMFA bool
}

// ConsentPageData contains data for the OAuth consent page template.
// The consent page is shown to an already-authenticated user so they can
// explicitly approve or deny an application's access request (CRIT-04).
type ConsentPageData struct {
	AppName             string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Scopes              []string
	// CSRFToken is the double-submit CSRF token (CRIT-03).
	CSRFToken string
	// ConsentToken is the HMAC-signed token that carries the authenticated
	// user's identity to the consent POST handler (CRIT-04).
	ConsentToken string
	// MaxAge is the OIDC max_age parameter (LOW-02).  -1 means "not specified".
	// Preserved as a hidden field so the consent POST can pass it to the service.
	MaxAge int
}

// ErrorPageData contains data for the error page template
type ErrorPageData struct {
	Title       string
	Message     string
	Description string
	ErrorCode   string
	ReturnURL   string
}

// AcceptInvitePageData contains data for the accept invite page template
type AcceptInvitePageData struct {
	Token   string
	Email   string
	Name    string
	AppName string
	Role    string
	Valid   bool
	Error   string
	Success string
}

// ForgotPasswordPageData contains data for the forgot password page template
type ForgotPasswordPageData struct {
	Email   string
	Error   string
	Success string
}

// ResetPasswordPageData contains data for the reset password page template
type ResetPasswordPageData struct {
	Token   string
	Email   string
	Valid   bool
	Error   string
	Success string
}

// RenderLogin renders the login page
func (s *TemplateService) RenderLogin(w http.ResponseWriter, data LoginPageData) error {
	// Parse scope string into descriptions
	if data.Scope != "" && len(data.Scopes) == 0 {
		data.Scopes = scopeDescriptions(data.Scope)
	}

	return s.render(w, s.loginTemplate, data)
}

// RenderConsent renders the OAuth consent page (CRIT-04).
func (s *TemplateService) RenderConsent(w http.ResponseWriter, data ConsentPageData) error {
	if data.Scope != "" && len(data.Scopes) == 0 {
		data.Scopes = scopeDescriptions(data.Scope)
	}
	return s.render(w, s.consentTemplate, data)
}

// RenderError renders the error page with a 400 Bad Request status
func (s *TemplateService) RenderError(w http.ResponseWriter, data ErrorPageData) error {
	return s.renderWithStatus(w, s.errorTemplate, data, http.StatusBadRequest)
}

// RenderAcceptInvite renders the accept invite page
func (s *TemplateService) RenderAcceptInvite(w http.ResponseWriter, data AcceptInvitePageData) error {
	return s.render(w, s.acceptInviteTemplate, data)
}

// RenderForgotPassword renders the forgot password page
func (s *TemplateService) RenderForgotPassword(w http.ResponseWriter, data ForgotPasswordPageData) error {
	return s.render(w, s.forgotPasswordTemplate, data)
}

// RenderResetPassword renders the reset password page
func (s *TemplateService) RenderResetPassword(w http.ResponseWriter, data ResetPasswordPageData) error {
	return s.render(w, s.resetPasswordTemplate, data)
}

func (s *TemplateService) render(w http.ResponseWriter, tmpl *template.Template, data interface{}) error {
	return s.renderWithStatus(w, tmpl, data, http.StatusOK)
}

func (s *TemplateService) renderWithStatus(w http.ResponseWriter, tmpl *template.Template, data interface{}, status int) error {
	// First render to a buffer to catch errors before writing to response
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, err := io.Copy(w, &buf)
	return err
}

// scopeDescriptions converts scope strings to human-readable descriptions
func scopeDescriptions(scope string) []string {
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
		} else if isAppScope(s) {
			// #336: an application-defined scope has no server-side description;
			// show it verbatim (the grammar admits only [a-z0-9:._-], and
			// html/template escapes the value anyway) so the user sees every
			// application permission they approve.
			descriptions = append(descriptions, "Use the application permission "+s)
		}
	}

	return descriptions
}
