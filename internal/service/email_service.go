package service

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// EmailService handles sending emails via SMTP
type EmailService interface {
	SendVerificationEmail(to, name, token string) error
	SendPasswordResetEmail(to, name, token string) error
	SendInviteEmail(to, appName, token string) error
	SendWelcomeEmail(to, name string) error
	SendAppCredentialsEmail(to, adminName, appName, clientID, clientSecret string) error
}

// SMTPConfig holds SMTP configuration
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Security string // "none", "starttls", "ssl"
	From     string
	BaseURL  string // Base URL for links (e.g., http://localhost:8080)
}

type emailService struct {
	config    SMTPConfig
	templates *emailTemplates
}

type emailTemplates struct {
	verification   *template.Template
	passwordReset  *template.Template
	invite         *template.Template
	welcome        *template.Template
	appCredentials *template.Template
}

// NewEmailService creates a new email service
func NewEmailService(config SMTPConfig) EmailService {
	return &emailService{
		config:    config,
		templates: parseEmailTemplates(),
	}
}

// SendVerificationEmail sends an email verification link
func (s *emailService) SendVerificationEmail(to, name, token string) error {
	logger.WithFields(logger.Fields{
		"email_type": "verification",
		"to":         to,
	}).Info("📧 Sending verification email")

	data := map[string]string{
		"Name":    name,
		"Link":    fmt.Sprintf("%s/api/auth/verify-email?token=%s", s.config.BaseURL, token),
		"BaseURL": s.config.BaseURL,
	}

	subject := "Verify your email address"
	body, err := s.renderTemplate(s.templates.verification, data)
	if err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "verification",
			"to":         to,
			"error":      err.Error(),
		}).Error("📧 Failed to render verification email template")
		return fmt.Errorf("failed to render verification email: %w", err)
	}

	if err := s.send(to, subject, body); err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "verification",
			"to":         to,
			"error":      err.Error(),
		}).Error("📧 Failed to send verification email")
		return err
	}

	logger.WithFields(logger.Fields{
		"email_type": "verification",
		"to":         to,
	}).Info("📧 Verification email sent successfully")
	return nil
}

// SendPasswordResetEmail sends a password reset link
func (s *emailService) SendPasswordResetEmail(to, name, token string) error {
	logger.WithFields(logger.Fields{
		"email_type": "password_reset",
		"to":         to,
	}).Info("📧 Sending password reset email")

	data := map[string]string{
		"Name":    name,
		"Link":    fmt.Sprintf("%s/auth/reset-password?token=%s", s.config.BaseURL, token),
		"BaseURL": s.config.BaseURL,
	}

	subject := "Reset your password"
	body, err := s.renderTemplate(s.templates.passwordReset, data)
	if err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "password_reset",
			"to":         to,
			"error":      err.Error(),
		}).Error("📧 Failed to render password reset email template")
		return fmt.Errorf("failed to render password reset email: %w", err)
	}

	if err := s.send(to, subject, body); err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "password_reset",
			"to":         to,
			"error":      err.Error(),
		}).Error("📧 Failed to send password reset email")
		return err
	}

	logger.WithFields(logger.Fields{
		"email_type": "password_reset",
		"to":         to,
	}).Info("📧 Password reset email sent successfully")
	return nil
}

// SendInviteEmail sends an invitation to join an app
func (s *emailService) SendInviteEmail(to, appName, token string) error {
	logger.WithFields(logger.Fields{
		"email_type": "invite",
		"to":         to,
		"app_name":   appName,
	}).Info("📧 Sending invite email")

	data := map[string]string{
		"AppName": appName,
		"Link":    fmt.Sprintf("%s/auth/accept-invite?token=%s", s.config.BaseURL, token),
		"BaseURL": s.config.BaseURL,
	}

	subject := fmt.Sprintf("You've been invited to %s", appName)
	body, err := s.renderTemplate(s.templates.invite, data)
	if err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "invite",
			"to":         to,
			"app_name":   appName,
			"error":      err.Error(),
		}).Error("📧 Failed to render invite email template")
		return fmt.Errorf("failed to render invite email: %w", err)
	}

	if err := s.send(to, subject, body); err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "invite",
			"to":         to,
			"app_name":   appName,
			"error":      err.Error(),
		}).Error("📧 Failed to send invite email")
		return err
	}

	logger.WithFields(logger.Fields{
		"email_type": "invite",
		"to":         to,
		"app_name":   appName,
	}).Info("📧 Invite email sent successfully")
	return nil
}

// SendWelcomeEmail sends a welcome email after verification
func (s *emailService) SendWelcomeEmail(to, name string) error {
	logger.WithFields(logger.Fields{
		"email_type": "welcome",
		"to":         to,
	}).Info("📧 Sending welcome email")

	data := map[string]string{
		"Name":    name,
		"BaseURL": s.config.BaseURL,
	}

	subject := "Welcome!"
	body, err := s.renderTemplate(s.templates.welcome, data)
	if err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "welcome",
			"to":         to,
			"error":      err.Error(),
		}).Error("📧 Failed to render welcome email template")
		return fmt.Errorf("failed to render welcome email: %w", err)
	}

	if err := s.send(to, subject, body); err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "welcome",
			"to":         to,
			"error":      err.Error(),
		}).Error("📧 Failed to send welcome email")
		return err
	}

	logger.WithFields(logger.Fields{
		"email_type": "welcome",
		"to":         to,
	}).Info("📧 Welcome email sent successfully")
	return nil
}

// SendAppCredentialsEmail sends app credentials to the admin
func (s *emailService) SendAppCredentialsEmail(to, adminName, appName, clientID, clientSecret string) error {
	logger.WithFields(logger.Fields{
		"email_type": "app_credentials",
		"to":         to,
		"app_name":   appName,
		"client_id":  clientID,
	}).Info("📧 Sending app credentials email")

	data := map[string]string{
		"AdminName":    adminName,
		"AppName":      appName,
		"ClientID":     clientID,
		"ClientSecret": clientSecret,
		"BaseURL":      s.config.BaseURL,
	}

	subject := fmt.Sprintf("Your OAuth2 credentials for %s", appName)
	body, err := s.renderTemplate(s.templates.appCredentials, data)
	if err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "app_credentials",
			"to":         to,
			"app_name":   appName,
			"error":      err.Error(),
		}).Error("📧 Failed to render app credentials email template")
		return fmt.Errorf("failed to render app credentials email: %w", err)
	}

	if err := s.send(to, subject, body); err != nil {
		logger.WithFields(logger.Fields{
			"email_type": "app_credentials",
			"to":         to,
			"app_name":   appName,
			"error":      err.Error(),
		}).Error("📧 Failed to send app credentials email")
		return err
	}

	logger.WithFields(logger.Fields{
		"email_type": "app_credentials",
		"to":         to,
		"app_name":   appName,
		"client_id":  clientID,
	}).Info("📧 App credentials email sent successfully")
	return nil
}

func (s *emailService) renderTemplate(tmpl *template.Template, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (s *emailService) send(to, subject, htmlBody string) error {
	// Build email headers
	headers := make(map[string]string)
	headers["From"] = s.config.From
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	// Build message
	var msg bytes.Buffer
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	logger.WithFields(logger.Fields{
		"smtp_host":     s.config.Host,
		"smtp_port":     s.config.Port,
		"smtp_security": s.config.Security,
		"from":          s.config.From,
		"to":            to,
		"subject":       subject,
	}).Debug("📧 Connecting to SMTP server")

	var auth smtp.Auth
	if s.config.Username != "" {
		auth = smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	}

	var err error
	switch strings.ToLower(s.config.Security) {
	case "ssl", "tls":
		err = s.sendWithTLS(addr, auth, to, msg.Bytes())
	case "starttls":
		err = s.sendWithStartTLS(addr, auth, to, msg.Bytes())
	default:
		err = smtp.SendMail(addr, auth, s.config.From, []string{to}, msg.Bytes())
	}

	if err != nil {
		logger.WithFields(logger.Fields{
			"smtp_host": s.config.Host,
			"smtp_port": s.config.Port,
			"to":        to,
			"error":     err.Error(),
		}).Error("📧 SMTP send failed")
		return err
	}

	return nil
}

func (s *emailService) sendWithTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: s.config.Host,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	return s.sendWithClient(client, auth, to, msg)
}

func (s *emailService) sendWithStartTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Close()

	tlsConfig := &tls.Config{
		ServerName: s.config.Host,
	}

	if err := client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}

	return s.sendWithClient(client, auth, to, msg)
}

func (s *emailService) sendWithClient(client *smtp.Client, auth smtp.Auth, to string, msg []byte) error {
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	if err := client.Mail(s.config.From); err != nil {
		return fmt.Errorf("SMTP MAIL command failed: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT command failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command failed: %w", err)
	}

	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("failed to write email body: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close email body: %w", err)
	}

	return client.Quit()
}

func parseEmailTemplates() *emailTemplates {
	return &emailTemplates{
		verification:   template.Must(template.New("verification").Parse(verificationEmailTemplate)),
		passwordReset:  template.Must(template.New("passwordReset").Parse(passwordResetEmailTemplate)),
		invite:         template.Must(template.New("invite").Parse(inviteEmailTemplate)),
		welcome:        template.Must(template.New("welcome").Parse(welcomeEmailTemplate)),
		appCredentials: template.Must(template.New("appCredentials").Parse(appCredentialsEmailTemplate)),
	}
}

// Email templates
const verificationEmailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #f9fafb; border-radius: 8px; padding: 40px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #4f46e5; margin: 0; }
        .content { background: white; border-radius: 8px; padding: 30px; margin-bottom: 20px; }
        .button { display: inline-block; background: #4f46e5; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 500; }
        .button:hover { background: #4338ca; }
        .footer { text-align: center; color: #6b7280; font-size: 14px; }
        .link { word-break: break-all; color: #4f46e5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verify Your Email</h1>
        </div>
        <div class="content">
            <p>Hi {{.Name}},</p>
            <p>Thank you for signing up! Please verify your email address by clicking the button below:</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{{.Link}}" class="button">Verify Email Address</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p class="link">{{.Link}}</p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create an account, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>This email was sent from {{.BaseURL}}</p>
        </div>
    </div>
</body>
</html>`

const passwordResetEmailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #f9fafb; border-radius: 8px; padding: 40px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #4f46e5; margin: 0; }
        .content { background: white; border-radius: 8px; padding: 30px; margin-bottom: 20px; }
        .button { display: inline-block; background: #4f46e5; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 500; }
        .button:hover { background: #4338ca; }
        .footer { text-align: center; color: #6b7280; font-size: 14px; }
        .link { word-break: break-all; color: #4f46e5; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 6px; padding: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reset Your Password</h1>
        </div>
        <div class="content">
            <p>Hi {{.Name}},</p>
            <p>We received a request to reset your password. Click the button below to choose a new password:</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{{.Link}}" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p class="link">{{.Link}}</p>
            <p>This link will expire in 1 hour.</p>
            <div class="warning">
                <strong>Didn't request this?</strong><br>
                If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.
            </div>
        </div>
        <div class="footer">
            <p>This email was sent from {{.BaseURL}}</p>
        </div>
    </div>
</body>
</html>`

const inviteEmailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>You're Invited!</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #f9fafb; border-radius: 8px; padding: 40px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #4f46e5; margin: 0; }
        .content { background: white; border-radius: 8px; padding: 30px; margin-bottom: 20px; }
        .button { display: inline-block; background: #4f46e5; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 500; }
        .button:hover { background: #4338ca; }
        .footer { text-align: center; color: #6b7280; font-size: 14px; }
        .link { word-break: break-all; color: #4f46e5; }
        .app-name { font-size: 24px; font-weight: bold; color: #4f46e5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>You're Invited!</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>You've been invited to join <span class="app-name">{{.AppName}}</span>.</p>
            <p>Click the button below to accept the invitation and set up your account:</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{{.Link}}" class="button">Accept Invitation</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p class="link">{{.Link}}</p>
            <p>This invitation will expire in 7 days.</p>
        </div>
        <div class="footer">
            <p>This email was sent from {{.BaseURL}}</p>
        </div>
    </div>
</body>
</html>`

const welcomeEmailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome!</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #f9fafb; border-radius: 8px; padding: 40px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #4f46e5; margin: 0; }
        .content { background: white; border-radius: 8px; padding: 30px; margin-bottom: 20px; }
        .footer { text-align: center; color: #6b7280; font-size: 14px; }
        .checkmark { font-size: 48px; text-align: center; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="checkmark">✅</div>
            <h1>Welcome!</h1>
        </div>
        <div class="content">
            <p>Hi {{.Name}},</p>
            <p>Your email has been verified and your account is now active!</p>
            <p>You can now log in and start using all the features available to you.</p>
            <p>Thank you for joining us!</p>
        </div>
        <div class="footer">
            <p>This email was sent from {{.BaseURL}}</p>
        </div>
    </div>
</body>
</html>`

const appCredentialsEmailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your OAuth2 App Credentials</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #f9fafb; border-radius: 8px; padding: 40px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #4f46e5; margin: 0; }
        .content { background: white; border-radius: 8px; padding: 30px; margin-bottom: 20px; }
        .footer { text-align: center; color: #6b7280; font-size: 14px; }
        .app-name { font-size: 24px; font-weight: bold; color: #4f46e5; }
        .credentials { background: #1e293b; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .credentials-row { display: flex; margin-bottom: 12px; }
        .credentials-row:last-child { margin-bottom: 0; }
        .credentials-label { color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
        .credentials-value { color: #f1f5f9; font-family: 'SF Mono', Monaco, 'Courier New', monospace; font-size: 14px; word-break: break-all; background: #0f172a; padding: 8px 12px; border-radius: 4px; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 6px; padding: 12px; margin-top: 20px; }
        .warning strong { color: #92400e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Your OAuth2 Credentials</h1>
        </div>
        <div class="content">
            <p>Hi {{.AdminName}},</p>
            <p>Your application <span class="app-name">{{.AppName}}</span> has been created successfully!</p>
            <p>Here are your OAuth2 credentials:</p>
            <div class="credentials">
                <div class="credentials-row">
                    <div style="flex: 1;">
                        <div class="credentials-label">Client ID</div>
                        <div class="credentials-value">{{.ClientID}}</div>
                    </div>
                </div>
                <div class="credentials-row">
                    <div style="flex: 1;">
                        <div class="credentials-label">Client Secret</div>
                        <div class="credentials-value">{{.ClientSecret}}</div>
                    </div>
                </div>
            </div>
            <div class="warning">
                <strong>Important Security Notice:</strong><br>
                Store these credentials securely. The client secret will not be shown again and cannot be retrieved. If you lose it, you will need to regenerate a new secret.
            </div>
            <p style="margin-top: 20px;">Use these credentials to configure OAuth2 authentication in your application.</p>
        </div>
        <div class="footer">
            <p>This email was sent from {{.BaseURL}}</p>
        </div>
    </div>
</body>
</html>`
