package service

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"mime/quotedprintable"
	"net/smtp"
	"strings"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// EmailService defines the interface for sending emails
type EmailService interface {
	SendVerificationEmail(to, name, appName, verifyURL string) error
	SendPasswordResetEmail(to, name, appName, resetURL string) error
	SendInvitationEmail(to, name, appName, inviterName, inviteURL string) error
	SendInviteEmail(to, appName, inviteURL string) error
	SendWelcomeEmail(to, name, appName string) error
	SendAppCredentialsEmail(to, name, appName, clientID, clientSecret string) error
	// SendMagicLinkEmail sends a passwordless single-use login link to the user.
	SendMagicLinkEmail(to, name, appName, magicURL string) error
}

// EmailConfig holds SMTP email service configuration
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

type smtpEmailService struct {
	config    EmailConfig
	templates *template.Template
}

// NewEmailService creates a new SMTP-based email service
func NewEmailService(config EmailConfig) EmailService {
	tmpl, err := template.New("emails").Parse(emailTemplates)
	if err != nil {
		// Templates are embedded constants, so this should never fail
		panic(fmt.Sprintf("failed to parse email templates: %v", err))
	}

	return &smtpEmailService{
		config:    config,
		templates: tmpl,
	}
}

// SendVerificationEmail sends an email verification link
func (s *smtpEmailService) SendVerificationEmail(to, name, appName, verifyURL string) error {
	displayAppName := appName
	if displayAppName == "" {
		displayAppName = "Socrate"
	}

	data := map[string]string{
		"Name":      name,
		"AppName":   displayAppName,
		"VerifyURL": verifyURL,
		"Year":      "2024 - 2026",
	}

	subject := fmt.Sprintf("Verify your email for %s", displayAppName)
	return s.sendTemplatedEmail(to, subject, "verification", data)
}

// SendPasswordResetEmail sends a password reset link
func (s *smtpEmailService) SendPasswordResetEmail(to, name, appName, resetURL string) error {
	displayAppName := appName
	if displayAppName == "" {
		displayAppName = "Socrate"
	}

	data := map[string]string{
		"Name":     name,
		"AppName":  displayAppName,
		"ResetURL": resetURL,
		"Year":     "2024 - 2026",
	}

	subject := fmt.Sprintf("Reset your password for %s", displayAppName)
	return s.sendTemplatedEmail(to, subject, "password_reset", data)
}

// SendInvitationEmail sends an app invitation
func (s *smtpEmailService) SendInvitationEmail(to, name, appName, inviterName, inviteURL string) error {
	displayName := name
	if displayName == "" {
		displayName = to
	}

	data := map[string]string{
		"Name":        displayName,
		"AppName":     appName,
		"InviterName": inviterName,
		"InviteURL":   inviteURL,
		"Year":        "2024 - 2026",
	}

	subject := fmt.Sprintf("You've been invited to join %s", appName)
	return s.sendTemplatedEmail(to, subject, "invitation", data)
}

// SendWelcomeEmail sends a welcome email after successful registration
func (s *smtpEmailService) SendWelcomeEmail(to, name, appName string) error {
	data := map[string]string{
		"Name":    name,
		"AppName": appName,
		"Year":    "2024 - 2026",
	}

	subject := fmt.Sprintf("Welcome to %s", appName)
	return s.sendTemplatedEmail(to, subject, "welcome", data)
}

// SendInviteEmail sends an invitation email (simplified version without inviter name)
func (s *smtpEmailService) SendInviteEmail(to, appName, inviteURL string) error {
	return s.SendInvitationEmail(to, to, appName, "The administrator", inviteURL)
}

// SendAppCredentialsEmail sends app credentials to the admin
func (s *smtpEmailService) SendAppCredentialsEmail(to, name, appName, clientID, clientSecret string) error {
	data := map[string]string{
		"Name":         name,
		"AppName":      appName,
		"ClientID":     clientID,
		"ClientSecret": clientSecret,
		"Year":         "2024 - 2026",
	}

	subject := fmt.Sprintf("Credentials for %s", appName)
	return s.sendTemplatedEmail(to, subject, "app_credentials", data)
}

// SendMagicLinkEmail sends a passwordless single-use login link to the user.
func (s *smtpEmailService) SendMagicLinkEmail(to, name, appName, magicURL string) error {
	displayName := name
	if displayName == "" {
		displayName = to
	}
	displayAppName := appName
	if displayAppName == "" {
		displayAppName = "Socrate"
	}

	data := map[string]string{
		"Name":     displayName,
		"AppName":  displayAppName,
		"MagicURL": magicURL,
		"Year":     "2024 - 2026",
	}

	subject := fmt.Sprintf("Your login link for %s", displayAppName)
	return s.sendTemplatedEmail(to, subject, "magic_link", data)
}

func (s *smtpEmailService) sendTemplatedEmail(to, subject, templateName string, data map[string]string) error {
	logger.Logger.WithFields(logger.Fields{
		"to":       to,
		"subject":  subject,
		"template": templateName,
	}).Info("📧 Sending email")

	var bodyBuffer bytes.Buffer
	if err := s.templates.ExecuteTemplate(&bodyBuffer, templateName, data); err != nil {
		return fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	if err := s.sendEmail(to, subject, bodyBuffer.String()); err != nil {
		logger.Logger.WithFields(logger.Fields{
			"to":    to,
			"error": err.Error(),
		}).Error("📧 Failed to send email")
		return err
	}

	logger.Logger.WithFields(logger.Fields{
		"to":      to,
		"subject": subject,
	}).Info("📧 Email sent successfully")
	return nil
}

func (s *smtpEmailService) sendEmail(to, subject, htmlBody string) error {
	// Build email headers
	headers := make(map[string]string)
	if s.config.FromName != "" {
		headers["From"] = fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromEmail)
	} else {
		headers["From"] = s.config.FromEmail
	}
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"
	// quoted-printable encodes the body so that SMTP transport never needs to
	// fold long lines itself.  Without this, a JWT token inside an href
	// attribute can be broken by a space injected at the 76-char boundary,
	// producing a %20 in the URL and an "invalid token" error on click.
	headers["Content-Transfer-Encoding"] = "quoted-printable"

	// Encode body as quoted-printable before building the message.
	var qpBuf bytes.Buffer
	qpw := quotedprintable.NewWriter(&qpBuf)
	if _, err := qpw.Write([]byte(htmlBody)); err != nil {
		return fmt.Errorf("failed to encode email body: %w", err)
	}
	if err := qpw.Close(); err != nil {
		return fmt.Errorf("failed to flush quoted-printable encoder: %w", err)
	}

	// Build message
	var message strings.Builder
	for k, v := range headers {
		fmt.Fprintf(&message, "%s: %s\r\n", k, v)
	}
	message.WriteString("\r\n")
	message.WriteString(qpBuf.String())

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)

	var auth smtp.Auth
	if s.config.SMTPUsername != "" {
		auth = smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)
	}

	switch s.config.SMTPSecurity {
	case "ssl", "tls":
		return s.sendEmailSSL(addr, auth, to, message.String())
	case "starttls":
		return s.sendEmailStartTLS(addr, auth, to, message.String())
	default:
		return smtp.SendMail(addr, auth, s.config.FromEmail, []string{to}, []byte(message.String()))
	}
}

func (s *smtpEmailService) sendEmailSSL(addr string, auth smtp.Auth, to, message string) error {
	tlsConfig := &tls.Config{
		ServerName: s.config.SMTPHost,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect via SSL: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client, err := smtp.NewClient(conn, s.config.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	if err := client.Mail(s.config.FromEmail); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return client.Quit()
}

func (s *smtpEmailService) sendEmailStartTLS(addr string, auth smtp.Auth, to, message string) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	tlsConfig := &tls.Config{
		ServerName: s.config.SMTPHost,
	}

	if err := client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("STARTTLS failed: %w", err)
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	if err := client.Mail(s.config.FromEmail); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return client.Quit()
}

// Email templates embedded in Go
const emailTemplates = `
{{define "verification"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email for {{.AppName}}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 40px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px; text-align: center; background-color: #4F46E5; border-radius: 8px 8px 0 0;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">{{.AppName}}</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="margin: 0 0 20px; color: #1a1a1a; font-size: 20px;">Verify your email address</h2>
                            <p style="margin: 0 0 20px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Hi {{.Name}},
                            </p>
                            <p style="margin: 0 0 30px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Thank you for signing up for <strong>{{.AppName}}</strong>. Please verify your email address by clicking the button below.
                            </p>
                            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 0 auto;">
                                <tr>
                                    <td style="border-radius: 6px; background-color: #4F46E5;">
                                        <a href="{{.VerifyURL}}" target="_blank" style="display: inline-block; padding: 14px 32px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 600;">Verify Email</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 30px 0 0; color: #6a6a6a; font-size: 14px; line-height: 1.5;">
                                If you didn't create an account with {{.AppName}}, you can safely ignore this email.
                            </p>
                            <p style="margin: 20px 0 0; color: #6a6a6a; font-size: 14px; line-height: 1.5;">
                                This link will expire in 24 hours.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 40px; background-color: #f9f9f9; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #9a9a9a; font-size: 12px;">
                                &copy; {{.Year}} {{.AppName}}. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
{{end}}

{{define "password_reset"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password for {{.AppName}}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 40px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px; text-align: center; background-color: #4F46E5; border-radius: 8px 8px 0 0;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">{{.AppName}}</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="margin: 0 0 20px; color: #1a1a1a; font-size: 20px;">Reset your password</h2>
                            <p style="margin: 0 0 20px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Hi {{.Name}},
                            </p>
                            <p style="margin: 0 0 30px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                We received a request to reset your password for <strong>{{.AppName}}</strong>. Click the button below to choose a new password.
                            </p>
                            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 0 auto;">
                                <tr>
                                    <td style="border-radius: 6px; background-color: #4F46E5;">
                                        <a href="{{.ResetURL}}" target="_blank" style="display: inline-block; padding: 14px 32px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 600;">Reset Password</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 30px 0 0; color: #6a6a6a; font-size: 14px; line-height: 1.5;">
                                If you didn't request a password reset for {{.AppName}}, you can safely ignore this email. Your password will not be changed.
                            </p>
                            <p style="margin: 20px 0 0; color: #6a6a6a; font-size: 14px; line-height: 1.5;">
                                This link will expire in 1 hour.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 40px; background-color: #f9f9f9; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #9a9a9a; font-size: 12px;">
                                &copy; {{.Year}} {{.AppName}}. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
{{end}}

{{define "invitation"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>You're Invited</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 40px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px; text-align: center; background-color: #4F46E5; border-radius: 8px 8px 0 0;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">Socrate</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="margin: 0 0 20px; color: #1a1a1a; font-size: 20px;">You've been invited!</h2>
                            <p style="margin: 0 0 20px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Hi {{.Name}},
                            </p>
                            <p style="margin: 0 0 30px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                <strong>{{.InviterName}}</strong> has invited you to join <strong>{{.AppName}}</strong>. Click the button below to accept the invitation and set up your account.
                            </p>
                            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 0 auto;">
                                <tr>
                                    <td style="border-radius: 6px; background-color: #4F46E5;">
                                        <a href="{{.InviteURL}}" target="_blank" style="display: inline-block; padding: 14px 32px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 600;">Accept Invitation</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 30px 0 0; color: #6a6a6a; font-size: 14px; line-height: 1.5;">
                                If you don't want to join, you can safely ignore this email.
                            </p>
                            <p style="margin: 20px 0 0; color: #6a6a6a; font-size: 14px; line-height: 1.5;">
                                This invitation will expire in 24 hours.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 40px; background-color: #f9f9f9; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #9a9a9a; font-size: 12px;">
                                &copy; {{.Year}} Socrate. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
{{end}}

{{define "welcome"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 40px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px; text-align: center; background-color: #4F46E5; border-radius: 8px 8px 0 0;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">Socrate</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="margin: 0 0 20px; color: #1a1a1a; font-size: 20px;">Welcome to {{.AppName}}!</h2>
                            <p style="margin: 0 0 20px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Hi {{.Name}},
                            </p>
                            <p style="margin: 0 0 30px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Your account has been successfully created. You're all set to start using {{.AppName}}.
                            </p>
                            <p style="margin: 0 0 20px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                If you have any questions, feel free to reach out to our support team.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 40px; background-color: #f9f9f9; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #9a9a9a; font-size: 12px;">
                                &copy; {{.Year}} Socrate. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
{{end}}

{{define "app_credentials"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>App Credentials</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 40px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px; text-align: center; background-color: #4F46E5; border-radius: 8px 8px 0 0;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">Socrate</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="margin: 0 0 20px; color: #1a1a1a; font-size: 20px;">Credentials for {{.AppName}}</h2>
                            <p style="margin: 0 0 20px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Hi {{.Name}},
                            </p>
                            <p style="margin: 0 0 20px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Your application credentials have been generated. Please store them securely.
                            </p>
                            <div style="background: #f3f4f6; border-radius: 8px; padding: 20px; margin: 20px 0;">
                                <p style="margin: 0 0 10px; color: #374151; font-size: 14px;"><strong>Client ID:</strong></p>
                                <p style="margin: 0 0 20px; color: #1f2937; font-size: 14px; font-family: monospace; word-break: break-all;">{{.ClientID}}</p>
                                <p style="margin: 0 0 10px; color: #374151; font-size: 14px;"><strong>Client Secret:</strong></p>
                                <p style="margin: 0; color: #1f2937; font-size: 14px; font-family: monospace; word-break: break-all;">{{.ClientSecret}}</p>
                            </div>
                            <p style="margin: 20px 0 0; color: #dc2626; font-size: 14px; line-height: 1.5;">
                                <strong>Important:</strong> The client secret will not be shown again. Please save it now.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 40px; background-color: #f9f9f9; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #9a9a9a; font-size: 12px;">
                                &copy; {{.Year}} Socrate. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
{{end}}

{{define "magic_link"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your login link for {{.AppName}}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 40px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px; text-align: center; background-color: #4F46E5; border-radius: 8px 8px 0 0;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">{{.AppName}}</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="margin: 0 0 20px; color: #1a1a1a; font-size: 20px;">Your login link</h2>
                            <p style="margin: 0 0 20px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Hi {{.Name}},
                            </p>
                            <p style="margin: 0 0 30px; color: #4a4a4a; font-size: 16px; line-height: 1.5;">
                                Click the button below to log in to <strong>{{.AppName}}</strong>. This link is single-use and expires in 15 minutes.
                            </p>
                            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 0 auto;">
                                <tr>
                                    <td style="border-radius: 6px; background-color: #4F46E5;">
                                        <a href="{{.MagicURL}}" target="_blank" style="display: inline-block; padding: 14px 32px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 600;">Log in to {{.AppName}}</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 30px 0 0; color: #6a6a6a; font-size: 14px; line-height: 1.5;">
                                If you did not request this link, you can safely ignore this email. Someone may have typed your email address by mistake.
                            </p>
                            <p style="margin: 20px 0 0; color: #6a6a6a; font-size: 14px; line-height: 1.5;">
                                <strong>Do not forward this email.</strong> The link can only be used once.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 40px; background-color: #f9f9f9; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #9a9a9a; font-size: 12px;">
                                &copy; {{.Year}} {{.AppName}}. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
{{end}}
`

// NoOpEmailService is a no-op implementation for development/testing
type NoOpEmailService struct {
	LastEmail *SentEmail
}

type SentEmail struct {
	To      string
	Subject string
	URL     string
}

// NewNoOpEmailService creates a no-op email service for development/testing
func NewNoOpEmailService() EmailService {
	return &NoOpEmailService{}
}

func (s *NoOpEmailService) SendVerificationEmail(to, name, appName, verifyURL string) error {
	s.LastEmail = &SentEmail{To: to, Subject: "Verify Email", URL: verifyURL}
	fmt.Printf("[EMAIL] Verification email to %s for %s: %s\n", to, appName, verifyURL)
	return nil
}

func (s *NoOpEmailService) SendPasswordResetEmail(to, name, appName, resetURL string) error {
	s.LastEmail = &SentEmail{To: to, Subject: "Reset Password", URL: resetURL}
	fmt.Printf("[EMAIL] Password reset email to %s for %s: %s\n", to, appName, resetURL)
	return nil
}

func (s *NoOpEmailService) SendInvitationEmail(to, name, appName, inviterName, inviteURL string) error {
	s.LastEmail = &SentEmail{To: to, Subject: "Invitation", URL: inviteURL}
	fmt.Printf("[EMAIL] Invitation email to %s for %s: %s\n", to, appName, inviteURL)
	return nil
}

func (s *NoOpEmailService) SendWelcomeEmail(to, name, appName string) error {
	s.LastEmail = &SentEmail{To: to, Subject: "Welcome", URL: ""}
	fmt.Printf("[EMAIL] Welcome email to %s for %s\n", to, appName)
	return nil
}

func (s *NoOpEmailService) SendInviteEmail(to, appName, inviteURL string) error {
	s.LastEmail = &SentEmail{To: to, Subject: "Invitation", URL: inviteURL}
	fmt.Printf("[EMAIL] Invite email to %s for %s: %s\n", to, appName, inviteURL)
	return nil
}

func (s *NoOpEmailService) SendAppCredentialsEmail(to, name, appName, clientID, clientSecret string) error {
	s.LastEmail = &SentEmail{To: to, Subject: "App Credentials", URL: ""}
	fmt.Printf("[EMAIL] App credentials email to %s (%s) for %s: client_id=%s\n", to, name, appName, clientID)
	return nil
}

func (s *NoOpEmailService) SendMagicLinkEmail(to, name, appName, magicURL string) error {
	s.LastEmail = &SentEmail{To: to, Subject: "Magic Link", URL: magicURL}
	fmt.Printf("[EMAIL] Magic link email to %s for %s: %s\n", to, appName, magicURL)
	return nil
}
