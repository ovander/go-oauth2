# CR: Email Service and Web UI for Authentication Flows

## Overview

This document describes the SMTP-based email service and web pages for authentication flows in Socrate. The email service handles sending verification, password reset, invitation, welcome, and app credentials emails. The web UI provides user-facing HTML pages for the complete authentication experience.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Client App    │────▶│     Socrate     │────▶│   SMTP Server   │
│                 │◀────│   Web Handler   │     │   (Email)       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │
         │   HTML Pages          │
         │◀─────────────────────▶│
         │                       │
         │   Form Submissions    │
         │─────────────────────▶ │
```

---

## Components

### 1. Email Service (`internal/service/email_service.go`)

**Purpose:** Send transactional emails for authentication flows.

#### Interface

```go
type EmailService interface {
    SendVerificationEmail(to, name, verifyURL string) error
    SendPasswordResetEmail(to, name, resetURL string) error
    SendInvitationEmail(to, name, appName, inviterName, inviteURL string) error
    SendInviteEmail(to, appName, inviteURL string) error
    SendWelcomeEmail(to, name, appName string) error
    SendAppCredentialsEmail(to, name, appName, clientID, clientSecret string) error
}
```

#### Configuration

```go
type EmailConfig struct {
    SMTPHost     string // SMTP server hostname
    SMTPPort     int    // SMTP port (25, 465, 587)
    SMTPUsername string // Authentication username
    SMTPPassword string // Authentication password
    SMTPSecurity string // "starttls", "ssl", or "none"
    FromEmail    string // Sender email address
    FromName     string // Sender display name
    BaseURL      string // Base URL for generating links
}
```

#### Security Modes

| Mode | Port | Description |
|------|------|-------------|
| `starttls` | 587 | Upgrade to TLS after connection (recommended) |
| `ssl` | 465 | Direct TLS connection |
| `none` | 25 | Plaintext (development only) |

#### Email Templates

Each email type has an HTML template with responsive design:

| Email Type | Subject | Template Variables | Method |
|------------|---------|-------------------|--------|
| Verification | "Verify your email address" | Name, VerifyURL | `SendVerificationEmail` |
| Password Reset | "Reset your password" | Name, ResetURL | `SendPasswordResetEmail` |
| Invitation | "You've been invited to join {App}" | Name, AppName, InviterName, InviteURL | `SendInvitationEmail` |
| Invitation (Simple) | "You've been invited to join {App}" | AppName, InviteURL | `SendInviteEmail` |
| Welcome | "Welcome to {App}" | Name, AppName | `SendWelcomeEmail` |
| App Credentials | "Credentials for {App}" | Name, AppName, ClientID, ClientSecret | `SendAppCredentialsEmail` |

#### NoOp Implementation

For development/testing without SMTP:

```go
// NewNoOpEmailService creates a no-op email service for development/testing
func NewNoOpEmailService() EmailService {
    return &NoOpEmailService{}
}
```

This implementation logs emails instead of sending them:
```
[EMAIL] Verification email to user@example.com: https://...
[EMAIL] Password reset email to user@example.com: https://...
```

---

### 2. Web Handler (`internal/web/handler.go`)

**Purpose:** Serve HTML pages for authentication flows.

#### Handler Structure

```go
type WebHandler struct {
    templates    map[string]*template.Template
    authService  service.AuthService
    userService  service.UserService
    appRepo      repository.AppRepository
    emailService service.EmailService
    tokenService *auth.TokenService
    baseURL      string
}
```

#### Constructor

```go
func NewWebHandler(
    authService service.AuthService,
    userService service.UserService,
    appRepo repository.AppRepository,
    emailService service.EmailService,
    tokenService *auth.TokenService,
    baseURL string,
) (*WebHandler, error)
```

#### Endpoints

| Route | Method | Handler | Purpose |
|-------|--------|---------|---------|
| `/auth/login` | GET | `LoginPage` | Display login form |
| `/auth/login` | POST | `LoginSubmit` | Process login |
| `/auth/signup` | GET | `SignupPage` | Display signup form |
| `/auth/signup` | POST | `SignupSubmit` | Process signup |
| `/auth/forgot-password` | GET | `ForgotPasswordPage` | Display forgot password form |
| `/auth/forgot-password` | POST | `ForgotPasswordSubmit` | Send reset email |
| `/auth/reset-password` | GET | `ResetPasswordPage` | Display reset password form |
| `/auth/reset-password` | POST | `ResetPasswordSubmit` | Process password reset |
| `/auth/verify-email` | GET | `VerifyEmailPage` | Verify email token |
| `/auth/invite` | GET | `AcceptInvitePage` | Display invitation acceptance form |
| `/auth/invite` | POST | `AcceptInviteSubmit` | Process invitation acceptance |

#### OAuth2 Integration

The login page preserves OAuth2 parameters for the authorization flow:

```go
func (h *WebHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
    data := map[string]interface{}{
        "ClientID":            r.URL.Query().Get("client_id"),
        "RedirectURI":         r.URL.Query().Get("redirect_uri"),
        "State":               r.URL.Query().Get("state"),
        "Scope":               r.URL.Query().Get("scope"),
        "ResponseType":        r.URL.Query().Get("response_type"),
        "CodeChallenge":       r.URL.Query().Get("code_challenge"),
        "CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
        "Nonce":               r.URL.Query().Get("nonce"),
    }
}
```

---

### 3. HTML Templates (`internal/web/templates/`)

Templates are embedded using Go's `embed` package:

```go
//go:embed templates/*.html
var templateFS embed.FS
```

#### Template Files

| File | Purpose |
|------|---------|
| `base.html` | Base layout with CSS styling |
| `login.html` | Login form |
| `signup.html` | Signup form |
| `forgot_password.html` | Forgot password form |
| `reset_password.html` | Reset password form |
| `verify_email.html` | Email verification result |
| `accept_invite.html` | Invitation acceptance form |

#### Design Features

- **Responsive layout** - Works on mobile and desktop
- **Clean, modern design** - Professional appearance with gradient background
- **Form validation** - Client-side validation for passwords
- **Error handling** - Clear error messages with styled alerts
- **Success states** - Confirmation messages after actions
- **Self-contained** - All CSS embedded in base template (no external dependencies)

#### Base Template Structure

```html
{{define "base"}}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}} - Socrate</title>
    <style>
        /* Embedded CSS for self-contained pages */
    </style>
</head>
<body>
    <div class="container">
        {{template "content" .}}
        <div class="footer">
            &copy; 2024 - 2026 Socrate. All rights reserved.
        </div>
    </div>
</body>
</html>
{{end}}
```

---

## Flow Diagrams

### Login Flow

```
User                    Web Handler                 Auth Service
  │                          │                           │
  │ GET /auth/login          │                           │
  │─────────────────────────▶│                           │
  │                          │                           │
  │    Login HTML Page       │                           │
  │◀─────────────────────────│                           │
  │                          │                           │
  │ POST /auth/login         │                           │
  │ (email, password)        │                           │
  │─────────────────────────▶│                           │
  │                          │ Login()                   │
  │                          │──────────────────────────▶│
  │                          │                           │
  │                          │ tokens                    │
  │                          │◀──────────────────────────│
  │                          │                           │
  │ Redirect with cookie     │                           │
  │◀─────────────────────────│                           │
```

### Password Reset Flow

```
User                    Web Handler                 Auth Service          Email Service
  │                          │                           │                      │
  │ GET /auth/forgot-password│                           │                      │
  │─────────────────────────▶│                           │                      │
  │                          │                           │                      │
  │    Forgot Password Page  │                           │                      │
  │◀─────────────────────────│                           │                      │
  │                          │                           │                      │
  │ POST (email)             │                           │                      │
  │─────────────────────────▶│                           │                      │
  │                          │ RequestPasswordReset()    │                      │
  │                          │──────────────────────────▶│                      │
  │                          │                           │                      │
  │                          │ SendPasswordResetEmail()  │                      │
  │                          │──────────────────────────────────────────────────▶│
  │                          │                           │                      │
  │    Success Page          │                           │                      │
  │◀─────────────────────────│                           │                      │
  │                          │                           │                      │
  │ (Email arrives)          │                           │                      │
  │                          │                           │                      │
  │ GET /auth/reset-password?token=xxx                   │                      │
  │─────────────────────────▶│                           │                      │
  │                          │                           │                      │
  │    Reset Password Form   │                           │                      │
  │◀─────────────────────────│                           │                      │
  │                          │                           │                      │
  │ POST (password)          │                           │                      │
  │─────────────────────────▶│                           │                      │
  │                          │ ResetPassword()           │                      │
  │                          │──────────────────────────▶│                      │
  │                          │                           │                      │
  │    Success Page          │                           │                      │
  │◀─────────────────────────│                           │                      │
```

---

## Configuration

### Environment Variables

```bash
# SMTP Configuration
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=noreply@example.com
SMTP_PASSWORD=secret
SMTP_SECURITY=starttls
FROM_EMAIL=noreply@example.com
FROM_NAME=Socrate

# Base URL for email links
OAUTH_ISSUER=https://auth.example.com
```

### Bootstrap Integration

```go
// Email service (nil if SMTP not configured)
var emailService service.EmailService
if cfg.SMTPHost != "" {
    emailService = service.NewEmailService(service.EmailConfig{
        SMTPHost:     cfg.SMTPHost,
        SMTPPort:     cfg.SMTPPort,
        SMTPUsername: cfg.SMTPUsername,
        SMTPPassword: cfg.SMTPPassword,
        SMTPSecurity: cfg.SMTPSecurity,
        FromEmail:    cfg.FromEmail,
        FromName:     cfg.FromName,
        BaseURL:      cfg.OAuthIssuer,
    })
}

// Web handler
webHandler, err := web.NewWebHandler(
    authService,
    userService,
    appRepo,
    emailService,
    tokenService,
    cfg.OAuthIssuer,
)
```

---

## Security Considerations

### Email Security

- **TLS Encryption** - All SMTP connections use TLS (STARTTLS or SSL)
- **No Email Enumeration** - Same response whether email exists or not
- **Token Expiration** - All email tokens have limited TTL
- **Single-Use Tokens** - Tokens are invalidated after use

### Web Security

- **Input Validation** - Server-side validation of all inputs
- **Password Requirements** - Minimum 8 characters enforced
- **Error Messages** - Generic errors to prevent information disclosure

### Template Security

- **Auto-escaping** - Go templates auto-escape HTML
- **Embedded Templates** - Templates compiled into binary
- **No External Resources** - All CSS inline for self-contained pages

---

## Files

| File | Purpose |
|------|---------|
| `internal/service/email_service.go` | SMTP email service + templates |
| `internal/web/handler.go` | Web page handlers |
| `internal/web/templates/base.html` | Base HTML template with CSS |
| `internal/web/templates/login.html` | Login page |
| `internal/web/templates/signup.html` | Signup page |
| `internal/web/templates/forgot_password.html` | Forgot password page |
| `internal/web/templates/reset_password.html` | Reset password page |
| `internal/web/templates/verify_email.html` | Email verification result |
| `internal/web/templates/accept_invite.html` | Invitation acceptance |

---

## Testing

### Manual Testing with MailHog

```bash
# Start MailHog (local SMTP)
docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog

# Configure
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_SECURITY=none
```

### Web Page Testing

1. Navigate to `http://localhost:8080/auth/login`
2. Test all form submissions
3. Verify email links work correctly

### NoOp Mode

For testing without SMTP, the NoOp email service logs instead of sending:

```go
emailService := service.NewNoOpEmailService()
```

---

## Router Integration

The WebHandler routes are registered in `internal/http/router.go`:

```go
r.Route("/auth", func(r chi.Router) {
    // Login flow
    r.Get("/login", webHandler.LoginPage)
    r.With(middleware.RateLimitMiddleware(config.LoginRateLimiter)).
        Post("/login", webHandler.LoginSubmit)

    // Signup flow
    r.Get("/signup", webHandler.SignupPage)
    r.With(middleware.RateLimitMiddleware(config.SignupRateLimiter)).
        Post("/signup", webHandler.SignupSubmit)

    // Password reset flow
    r.Get("/forgot-password", webHandler.ForgotPasswordPage)
    r.Post("/forgot-password", webHandler.ForgotPasswordSubmit)
    r.Get("/reset-password", webHandler.ResetPasswordPage)
    r.Post("/reset-password", webHandler.ResetPasswordSubmit)

    // Email verification
    r.Get("/verify-email", webHandler.VerifyEmailPage)

    // Invitation acceptance
    r.Get("/invite", webHandler.AcceptInvitePage)
    r.Post("/invite", webHandler.AcceptInviteSubmit)
})
```

---

## Summary

The Email Service and Web UI provide a complete, self-contained authentication experience:

| Feature | Implementation |
|---------|----------------|
| Email sending | SMTP with TLS support |
| Email templates | Embedded HTML with responsive design |
| Login page | OAuth2 parameter preservation |
| Signup page | Email verification flow |
| Password reset | Token-based secure reset |
| Invitation acceptance | Combined email verification + password setup |
| Security | Input validation, token expiration, no enumeration |
