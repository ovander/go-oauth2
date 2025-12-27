package service

import (
	"bytes"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/ovandermoten/go-oauth2/web"
)

// TemplateService handles rendering of HTML templates
type TemplateService struct {
	loginTemplate *template.Template
	errorTemplate *template.Template
}

// NewTemplateService creates a new template service
func NewTemplateService() *TemplateService {
	// Parse login template with base
	loginTmpl := template.Must(template.New("login").Parse(mustReadTemplate("templates/base.html")))
	template.Must(loginTmpl.Parse(mustReadTemplate("templates/login.html")))

	// Parse error template with base
	errorTmpl := template.Must(template.New("error").Parse(mustReadTemplate("templates/base.html")))
	template.Must(errorTmpl.Parse(mustReadTemplate("templates/error.html")))

	return &TemplateService{
		loginTemplate: loginTmpl,
		errorTemplate: errorTmpl,
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
}

// ErrorPageData contains data for the error page template
type ErrorPageData struct {
	Title       string
	Message     string
	Description string
	ErrorCode   string
	ReturnURL   string
}

// RenderLogin renders the login page
func (s *TemplateService) RenderLogin(w http.ResponseWriter, data LoginPageData) error {
	// Parse scope string into descriptions
	if data.Scope != "" && len(data.Scopes) == 0 {
		data.Scopes = scopeDescriptions(data.Scope)
	}

	return s.render(w, s.loginTemplate, data)
}

// RenderError renders the error page
func (s *TemplateService) RenderError(w http.ResponseWriter, data ErrorPageData) error {
	return s.render(w, s.errorTemplate, data)
}

func (s *TemplateService) render(w http.ResponseWriter, tmpl *template.Template, data interface{}) error {
	// First render to a buffer to catch errors before writing to response
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
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
		}
	}

	return descriptions
}
