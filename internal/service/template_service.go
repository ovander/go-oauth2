package service

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"github.com/ovandermoten/go-oauth2/web"
)

// TemplateService handles rendering of HTML templates
type TemplateService struct {
	templates *template.Template
}

// NewTemplateService creates a new template service
func NewTemplateService() *TemplateService {
	return &TemplateService{
		templates: web.Templates,
	}
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

	return s.render(w, "login.html", data)
}

// RenderError renders the error page
func (s *TemplateService) RenderError(w http.ResponseWriter, data ErrorPageData) error {
	return s.render(w, "error.html", data)
}

func (s *TemplateService) render(w http.ResponseWriter, name string, data interface{}) error {
	// First render to a buffer to catch errors before writing to response
	var buf bytes.Buffer

	// Execute base template with the specific template
	err := s.templates.ExecuteTemplate(&buf, "base.html", data)
	if err != nil {
		return err
	}

	// Now render the specific template content
	buf.Reset()
	err = s.templates.ExecuteTemplate(&buf, name, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Combine base and content
	return s.renderWithBase(w, name, data)
}

func (s *TemplateService) renderWithBase(w http.ResponseWriter, contentTemplate string, data interface{}) error {
	// Create a new template that includes base
	tmpl := template.Must(template.New("page").Parse(`
{{template "base.html" .}}
`))

	// Clone and add the content template
	tmpl, err := tmpl.AddParseTree("base.html", s.templates.Lookup("base.html").Tree)
	if err != nil {
		return err
	}

	contentTmpl := s.templates.Lookup(contentTemplate)
	if contentTmpl != nil {
		tmpl, err = tmpl.AddParseTree(contentTemplate, contentTmpl.Tree)
		if err != nil {
			return err
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return tmpl.ExecuteTemplate(w, "base.html", data)
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
	}

	for _, s := range scopes {
		if desc, ok := scopeMap[s]; ok {
			descriptions = append(descriptions, desc)
		}
	}

	return descriptions
}
