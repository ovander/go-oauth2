package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// AuthService defines the authentication service interface
type AuthService interface {
	Signup(ctx context.Context, req dto.SignupRequest) (*model.User, string, error)
	VerifyEmail(ctx context.Context, token string) error
	Login(ctx context.Context, req dto.LoginRequest) (*dto.LoginResponse, error)
	AdminLogin(ctx context.Context, req dto.AdminLoginRequest) (*dto.LoginResponse, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error)
	Logout(ctx context.Context, userID uint) error
	RequestPasswordReset(ctx context.Context, email string, appCtx *auth.AppContext) (string, error)
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID uint, currentPassword, newPassword string) error
	ValidateInviteToken(ctx context.Context, token string) (*dto.InviteValidationResponse, error)
	AcceptInvite(ctx context.Context, token, name, password string) (*dto.LoginResponse, error)
	// WithMFA enables login step-up: when set, a user with MFA enabled must
	// present a valid TOTP code (LoginRequest.MFACode) to complete login.
	// Optional and nil-safe — without it, login behaviour is unchanged. Returns
	// the receiver for chaining. RFC-011 / EPIC-9.
	WithMFA(mfa MFAService) AuthService
}

type authService struct {
	userRepo          repository.UserRepository
	appRepo           repository.AppRepository
	userAppRoleRepo   repository.UserAppRoleRepository
	usedTokenRepo     repository.UsedTokenRepository
	auditRepo         repository.SecurityAuditLogRepository
	tokenService      *auth.TokenService
	emailService      EmailService
	maxFailedAttempts int
	lockoutDuration   time.Duration
	mfa               MFAService // optional; nil disables login step-up
}

// WithMFA wires the MFA verifier for login step-up and returns the receiver.
func (s *authService) WithMFA(mfa MFAService) AuthService {
	s.mfa = mfa
	return s
}

// stepUpMFA applies login step-up after the password has been verified. It is a
// no-op when step-up is not configured or the user has not enabled MFA.
// Otherwise an empty code yields ErrMFARequired (the client should prompt for a
// code and retry) and a wrong code yields ErrMFAInvalidCode.
func (s *authService) stepUpMFA(ctx context.Context, user *model.User, code string) error {
	if s.mfa == nil || !user.MFAEnabled {
		return nil
	}
	if strings.TrimSpace(code) == "" {
		return ErrMFARequired
	}
	if err := s.mfa.Verify(ctx, user.ID, code); err != nil {
		return ErrMFAInvalidCode
	}
	return nil
}

// AuthServiceConfig holds auth service configuration
type AuthServiceConfig struct {
	MaxFailedAttempts int
	LockoutDuration   time.Duration
}

// NewAuthService creates a new auth service
func NewAuthService(
	userRepo repository.UserRepository,
	appRepo repository.AppRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	tokenService *auth.TokenService,
	config AuthServiceConfig,
) AuthService {
	logger.WithFields(logger.Fields{
		"service":             "auth",
		"max_failed_attempts": config.MaxFailedAttempts,
		"lockout_duration":    config.LockoutDuration.String(),
		"used_token_tracking": false,
		"audit_logging":       false,
		"email_enabled":       false,
	}).Info("✅ Auth service initialized")

	return &authService{
		userRepo:          userRepo,
		appRepo:           appRepo,
		userAppRoleRepo:   userAppRoleRepo,
		usedTokenRepo:     nil, // Optional - will skip single-use check if nil
		auditRepo:         nil, // Optional - will skip audit logging if nil
		tokenService:      tokenService,
		maxFailedAttempts: config.MaxFailedAttempts,
		lockoutDuration:   config.LockoutDuration,
	}
}

// NewAuthServiceWithUsedTokenRepo creates a new auth service with used token tracking
func NewAuthServiceWithUsedTokenRepo(
	userRepo repository.UserRepository,
	appRepo repository.AppRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	usedTokenRepo repository.UsedTokenRepository,
	tokenService *auth.TokenService,
	config AuthServiceConfig,
) AuthService {
	logger.WithFields(logger.Fields{
		"service":             "auth",
		"max_failed_attempts": config.MaxFailedAttempts,
		"lockout_duration":    config.LockoutDuration.String(),
		"used_token_tracking": true,
		"audit_logging":       false,
		"email_enabled":       false,
	}).Info("✅ Auth service initialized")

	return &authService{
		userRepo:          userRepo,
		appRepo:           appRepo,
		userAppRoleRepo:   userAppRoleRepo,
		usedTokenRepo:     usedTokenRepo,
		auditRepo:         nil,
		tokenService:      tokenService,
		maxFailedAttempts: config.MaxFailedAttempts,
		lockoutDuration:   config.LockoutDuration,
	}
}

// NewAuthServiceFull creates a new auth service with all optional features
func NewAuthServiceFull(
	userRepo repository.UserRepository,
	appRepo repository.AppRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	usedTokenRepo repository.UsedTokenRepository,
	auditRepo repository.SecurityAuditLogRepository,
	tokenService *auth.TokenService,
	emailService EmailService,
	config AuthServiceConfig,
) AuthService {
	logger.WithFields(logger.Fields{
		"service":             "auth",
		"max_failed_attempts": config.MaxFailedAttempts,
		"lockout_duration":    config.LockoutDuration.String(),
		"used_token_tracking": usedTokenRepo != nil,
		"audit_logging":       auditRepo != nil,
		"email_enabled":       emailService != nil,
	}).Info("✅ Auth service initialized")

	return &authService{
		userRepo:          userRepo,
		appRepo:           appRepo,
		userAppRoleRepo:   userAppRoleRepo,
		usedTokenRepo:     usedTokenRepo,
		auditRepo:         auditRepo,
		tokenService:      tokenService,
		emailService:      emailService,
		maxFailedAttempts: config.MaxFailedAttempts,
		lockoutDuration:   config.LockoutDuration,
	}
}

// Signup creates a new user account
func (s *authService) Signup(ctx context.Context, req dto.SignupRequest) (*model.User, string, error) {
	if err := auth.ValidatePassword(req.Password); err != nil {
		return nil, "", fmt.Errorf("password validation failed: %w", err)
	}

	existing, _ := s.userRepo.FindByEmail(ctx, req.Email)
	if existing != nil {
		return nil, "", fmt.Errorf("%w: %s", ErrEmailAlreadyExists, req.Email)
	}

	app, err := s.appRepo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: client_id=%s", ErrAppNotFound, req.ClientID)
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	user := &model.User{
		Email:          req.Email,
		Name:           req.Name,
		HashedPassword: hashedPassword,
		Role:           model.UserRoleUser,
		IsVerified:     false,
		TokenVersion:   1,
		Source:         "signup",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	userAppRole := &model.UserAppRole{
		UserID:    user.ID,
		AppID:     app.ID,
		Role:      model.AppRoleUser,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.userAppRoleRepo.Create(ctx, userAppRole); err != nil {
		return nil, "", fmt.Errorf("failed to assign user role: %w", err)
	}

	// Generate verification token with app context
	appCtx := &auth.AppContext{
		AppID:   app.ID,
		AppName: app.Name,
	}
	if len(app.RedirectURIs) > 0 {
		appCtx.RedirectURI = app.RedirectURIs[0]
	}

	verifyToken, err := s.tokenService.GenerateEmailVerificationToken(user.Email, user.ID, appCtx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Send verification email with app name
	if s.emailService != nil {
		verifyURL := s.tokenService.GetIssuer() + "/auth/verify-email?token=" + verifyToken
		if err := s.emailService.SendVerificationEmail(user.Email, user.Name, app.Name, verifyURL); err != nil {
			// Log but don't fail - user can request resend
			s.logSecurityEvent(ctx, model.SecurityEventEmailSendFailed, &user.ID, &app.ID, false, map[string]interface{}{
				"email": user.Email,
				"type":  "verification",
				"error": err.Error(),
			})
		}
	}

	// Log user registration
	s.logSecurityEvent(ctx, model.SecurityEventUserRegistered, &user.ID, &app.ID, true, map[string]interface{}{
		"email": user.Email,
	})

	return user, verifyToken, nil
}

// VerifyEmail verifies a user's email address
func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	claims, err := s.tokenService.VerifyEmailToken(token)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.Type != "email_verification" || claims.Action != "verify" {
		return fmt.Errorf("%w: wrong token type", ErrInvalidToken)
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid subject", ErrInvalidToken)
	}

	// Atomically claim this token via INSERT … ON CONFLICT DO NOTHING.
	// This eliminates the TOCTOU race: two concurrent requests racing on the
	// same JTI will both try to insert; only one succeeds (RowsAffected==1).
	if s.usedTokenRepo != nil {
		if err := s.usedTokenRepo.MarkAsUsed(ctx, claims.ID, claims.Type, uint(userID), claims.ExpiresAt.Time); err != nil {
			if errors.Is(err, repository.ErrTokenAlreadyUsed) {
				return ErrTokenAlreadyUsed
			}
			return fmt.Errorf("failed to claim token: %w", err)
		}
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	user.IsVerified = true
	now := time.Now()
	user.ConfirmedAt = &now
	user.UpdatedAt = now

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to verify user: %w", err)
	}

	// Log email verification
	s.logSecurityEvent(ctx, model.SecurityEventEmailVerified, &user.ID, nil, true, map[string]interface{}{
		"email": user.Email,
	})

	return nil
}

// Login authenticates a user
func (s *authService) Login(ctx context.Context, req dto.LoginRequest) (*dto.LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if user.IsLocked() {
		return nil, fmt.Errorf("%w: try again later", ErrAccountLocked)
	}

	if !auth.CheckPassword(req.Password, user.HashedPassword) {
		if err := s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID); err != nil {
			logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
		}
		user, _ = s.userRepo.FindByID(ctx, user.ID)
		if user.FailedLoginAttempts >= s.maxFailedAttempts {
			lockUntil := time.Now().Add(s.lockoutDuration)
			if err := s.userRepo.LockAccount(ctx, user.ID, &lockUntil); err != nil {
				logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
			}
			// Log account lockout
			s.logSecurityEvent(ctx, model.SecurityEventAccountLocked, &user.ID, nil, false, map[string]interface{}{
				"email":           user.Email,
				"failed_attempts": user.FailedLoginAttempts,
			})
			return nil, ErrAccountLocked
		}
		// Log failed login attempt
		s.logSecurityEvent(ctx, model.SecurityEventLoginFailed, &user.ID, nil, false, map[string]interface{}{
			"email":           user.Email,
			"failed_attempts": user.FailedLoginAttempts,
		})
		return nil, ErrInvalidCredentials
	}

	if !user.IsVerified {
		return nil, fmt.Errorf("%w: please verify your email first", ErrUserNotVerified)
	}

	// Login step-up (RFC-011): an MFA-enrolled user must present a valid TOTP code.
	if err := s.stepUpMFA(ctx, user, req.MFACode); err != nil {
		if errors.Is(err, ErrMFAInvalidCode) {
			s.logSecurityEvent(ctx, model.SecurityEventLoginFailed, &user.ID, nil, false, map[string]interface{}{
				"email":  user.Email,
				"reason": "mfa_invalid",
			})
		}
		return nil, err
	}

	// App-specific login - requires app_client_id
	app, err := s.appRepo.FindByClientID(ctx, req.AppClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, req.AppClientID)
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: user has no access to app", ErrRoleNotFound)
	}

	appRoles, err := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if err != nil {
		appRoles = make(map[string]string)
	}

	// Reset failed attempts and update last login
	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
		logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}
	now := time.Now()
	user.LastLogin = &now
	user.LastLoginAttempt = &now
	user.UpdatedAt = now
	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}

	tokenSet, err := s.tokenService.GenerateTokenSet(
		user, app, string(userAppRole.Role),
		"openid email profile offline_access",
		appRoles, "", now.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Log successful login
	s.logSecurityEvent(ctx, model.SecurityEventLoginSuccess, &user.ID, &app.ID, true, map[string]interface{}{
		"email": user.Email,
	})

	return &dto.LoginResponse{
		AccessToken:        tokenSet.AccessToken,
		RefreshToken:       tokenSet.RefreshToken,
		IDToken:            tokenSet.IDToken,
		TokenType:          "Bearer",
		ExpiresIn:          tokenSet.ExpiresIn,
		UserID:             user.ID,
		App:                &dto.AppResponse{ID: app.ID, Name: app.Name, ClientID: app.ClientID},
		Roles:              []string{string(userAppRole.Role)},
		AppRoles:           appRoles,
		MustChangePassword: user.MustChangePassword,
	}, nil
}

// AdminLogin authenticates an admin user for the admin portal (no app context)
func (s *authService) AdminLogin(ctx context.Context, req dto.AdminLoginRequest) (*dto.LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if user.IsLocked() {
		return nil, fmt.Errorf("%w: try again later", ErrAccountLocked)
	}

	if !auth.CheckPassword(req.Password, user.HashedPassword) {
		if err := s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID); err != nil {
			logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
		}
		user, _ = s.userRepo.FindByID(ctx, user.ID)
		if user.FailedLoginAttempts >= s.maxFailedAttempts {
			lockUntil := time.Now().Add(s.lockoutDuration)
			if err := s.userRepo.LockAccount(ctx, user.ID, &lockUntil); err != nil {
				logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
			}
			s.logSecurityEvent(ctx, model.SecurityEventAccountLocked, &user.ID, nil, false, map[string]interface{}{
				"email":           user.Email,
				"failed_attempts": user.FailedLoginAttempts,
				"login_type":      "admin_portal",
			})
			return nil, ErrAccountLocked
		}
		s.logSecurityEvent(ctx, model.SecurityEventLoginFailed, &user.ID, nil, false, map[string]interface{}{
			"email":           user.Email,
			"failed_attempts": user.FailedLoginAttempts,
			"login_type":      "admin_portal",
		})
		return nil, ErrInvalidCredentials
	}

	if !user.IsVerified {
		return nil, fmt.Errorf("%w: please verify your email first", ErrUserNotVerified)
	}

	// Only allow superadmins to use admin portal login
	// App admins should use the regular /api/auth/login with app_client_id
	if user.Role != model.UserRoleSuperadmin {
		s.logSecurityEvent(ctx, model.SecurityEventLoginFailed, &user.ID, nil, false, map[string]interface{}{
			"email":      user.Email,
			"login_type": "admin_portal",
			"reason":     "not_superadmin",
		})
		return nil, ErrNotAdmin
	}

	// Login step-up (RFC-011): an MFA-enrolled admin must present a valid TOTP code.
	if err := s.stepUpMFA(ctx, user, req.MFACode); err != nil {
		if errors.Is(err, ErrMFAInvalidCode) {
			s.logSecurityEvent(ctx, model.SecurityEventLoginFailed, &user.ID, nil, false, map[string]interface{}{
				"email":      user.Email,
				"login_type": "admin_portal",
				"reason":     "mfa_invalid",
			})
		}
		return nil, err
	}

	// Reset failed attempts and update last login
	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
		logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}
	now := time.Now()
	user.LastLogin = &now
	user.LastLoginAttempt = &now
	user.UpdatedAt = now
	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}

	// Create a virtual "admin-portal" app for token generation
	adminApp := &model.App{
		ID:       0,
		ClientID: "admin-portal",
		Name:     "Admin Portal",
	}

	tokenSet, err := s.tokenService.GenerateTokenSet(
		user, adminApp, string(user.Role),
		"openid email profile offline_access",
		make(map[string]string), "", now.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Log successful admin login
	s.logSecurityEvent(ctx, model.SecurityEventLoginSuccess, &user.ID, nil, true, map[string]interface{}{
		"email":      user.Email,
		"login_type": "admin_portal",
	})

	return &dto.LoginResponse{
		AccessToken:        tokenSet.AccessToken,
		RefreshToken:       tokenSet.RefreshToken,
		IDToken:            tokenSet.IDToken,
		TokenType:          "Bearer",
		ExpiresIn:          tokenSet.ExpiresIn,
		UserID:             user.ID,
		App:                nil, // No app context for admin portal
		Roles:              []string{string(user.Role)},
		AppRoles:           make(map[string]string),
		MustChangePassword: user.MustChangePassword,
	}, nil
}

// RefreshTokens refreshes the token set
func (s *authService) RefreshTokens(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error) {
	claims, err := s.tokenService.VerifyRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid subject", ErrInvalidToken)
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return nil, fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	if user.TokenVersion != claims.Ver {
		return nil, fmt.Errorf("%w: token has been revoked", ErrInvalidToken)
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, clientID)
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: user has no access to app", ErrRoleNotFound)
	}

	appRoles, _ := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if appRoles == nil {
		appRoles = make(map[string]string)
	}

	tokenSet, err := s.tokenService.GenerateTokenSet(
		user, app, string(userAppRole.Role),
		claims.Scope, appRoles, "", claims.AuthTime,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &dto.RefreshResponse{
		AccessToken:  tokenSet.AccessToken,
		RefreshToken: tokenSet.RefreshToken,
		IDToken:      tokenSet.IDToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokenSet.ExpiresIn,
	}, nil
}

// Logout invalidates all user tokens
func (s *authService) Logout(ctx context.Context, userID uint) error {
	if err := s.userRepo.IncrementTokenVersion(ctx, userID); err != nil {
		return fmt.Errorf("failed to logout user: %w", err)
	}

	// Log logout (all tokens revoked)
	s.logSecurityEvent(ctx, model.SecurityEventTokenRevokedAll, &userID, nil, true, nil)

	return nil
}

// RequestPasswordReset initiates a password reset and returns the token
// Note: Email sending is handled by the caller to allow proper app context
func (s *authService) RequestPasswordReset(ctx context.Context, email string, appCtx *auth.AppContext) (string, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// Don't reveal if email exists - return empty string without error
		return "", nil
	}

	token, err := s.tokenService.GeneratePasswordResetToken(user.Email, user.ID, appCtx)
	if err != nil {
		return "", fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Log password reset request
	var appID *uint
	if appCtx != nil {
		appID = &appCtx.AppID
	}
	s.logSecurityEvent(ctx, model.SecurityEventPasswordResetReq, &user.ID, appID, true, map[string]interface{}{
		"email": user.Email,
	})

	return token, nil
}

// ResetPassword resets a user's password
func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	claims, err := s.tokenService.VerifyEmailToken(token)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.Type != "password_reset" || claims.Action != "reset" {
		return fmt.Errorf("%w: wrong token type", ErrInvalidToken)
	}

	if err := auth.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid subject", ErrInvalidToken)
	}

	// Atomically claim this token before making any state changes.
	if s.usedTokenRepo != nil {
		if err := s.usedTokenRepo.MarkAsUsed(ctx, claims.ID, claims.Type, uint(userID), claims.ExpiresAt.Time); err != nil {
			if errors.Is(err, repository.ErrTokenAlreadyUsed) {
				return ErrTokenAlreadyUsed
			}
			return fmt.Errorf("failed to claim token: %w", err)
		}
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	hashedPassword, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	user.HashedPassword = hashedPassword
	user.MustChangePassword = false // Clear the forced password change flag
	user.PasswordChangedAt = &now
	user.UpdatedAt = now

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all existing tokens
	if err := s.userRepo.IncrementTokenVersion(ctx, user.ID); err != nil {
		return fmt.Errorf("failed to revoke tokens: %w", err)
	}

	// Log password change
	s.logSecurityEvent(ctx, model.SecurityEventPasswordChanged, &user.ID, nil, true, map[string]interface{}{
		"email": user.Email,
	})

	return nil
}

// ChangePassword changes the password for an authenticated user
func (s *authService) ChangePassword(ctx context.Context, userID uint, currentPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	// Verify current password
	if !auth.CheckPassword(currentPassword, user.HashedPassword) {
		return ErrInvalidCredentials
	}

	// Validate new password
	if err := auth.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// Ensure new password is different from current
	if auth.CheckPassword(newPassword, user.HashedPassword) {
		return fmt.Errorf("new password must be different from current password")
	}

	hashedPassword, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	user.HashedPassword = hashedPassword
	user.MustChangePassword = false
	user.PasswordChangedAt = &now
	user.UpdatedAt = now

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all existing tokens (user must re-login)
	if err := s.userRepo.IncrementTokenVersion(ctx, user.ID); err != nil {
		return fmt.Errorf("failed to revoke tokens: %w", err)
	}

	// Log password change
	s.logSecurityEvent(ctx, model.SecurityEventPasswordChanged, &user.ID, nil, true, map[string]interface{}{
		"email":  user.Email,
		"source": "change_password",
	})

	return nil
}

// ValidateInviteToken validates an invite token
func (s *authService) ValidateInviteToken(ctx context.Context, token string) (*dto.InviteValidationResponse, error) {
	claims, err := s.tokenService.VerifyInviteToken(token)
	if err != nil {
		return &dto.InviteValidationResponse{Valid: false}, nil
	}

	// Check if token has already been used
	if s.usedTokenRepo != nil {
		used, _ := s.usedTokenRepo.IsUsed(ctx, claims.ID)
		if used {
			return &dto.InviteValidationResponse{Valid: false}, nil
		}
	}

	app, err := s.appRepo.FindByID(ctx, claims.AppID)
	if err != nil {
		return &dto.InviteValidationResponse{Valid: false}, nil
	}

	return &dto.InviteValidationResponse{
		Valid:     true,
		Email:     claims.Email,
		AppName:   app.Name,
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}

// AcceptInvite accepts an invite and creates/updates a user
func (s *authService) AcceptInvite(ctx context.Context, token, name, password string) (*dto.LoginResponse, error) {
	claims, err := s.tokenService.VerifyInviteToken(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Validate role from token
	if !model.IsValidAppRole(claims.Role) {
		return nil, fmt.Errorf("invalid role in invite token: %s", claims.Role)
	}

	if err := auth.ValidatePassword(password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Atomically claim this token before creating/updating the user.
	if s.usedTokenRepo != nil {
		if err := s.usedTokenRepo.MarkAsUsed(ctx, claims.ID, claims.Type, 0, claims.ExpiresAt.Time); err != nil {
			if errors.Is(err, repository.ErrTokenAlreadyUsed) {
				return nil, ErrTokenAlreadyUsed
			}
			return nil, fmt.Errorf("failed to claim token: %w", err)
		}
	}

	now := time.Now()
	// Use provided name or fall back to email
	userName := name
	if userName == "" {
		userName = claims.Email
	}

	user, err := s.userRepo.FindByEmail(ctx, claims.Email)
	if err != nil {
		// Create new user
		user = &model.User{
			Email:          claims.Email,
			Name:           userName,
			HashedPassword: hashedPassword,
			Role:           model.UserRoleUser,
			IsVerified:     true,
			TokenVersion:   1,
			Source:         "invite",
			ConfirmedAt:    &now,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		if err := s.userRepo.Create(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	} else {
		// Update existing user
		user.HashedPassword = hashedPassword
		user.IsVerified = true
		user.ConfirmedAt = &now
		user.UpdatedAt = now
		if userName != "" && userName != claims.Email {
			user.Name = userName
		}

		if err := s.userRepo.Update(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
	}

	app, err := s.appRepo.FindByID(ctx, claims.AppID)
	if err != nil {
		return nil, fmt.Errorf("%w: app_id=%d", ErrAppNotFound, claims.AppID)
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		userAppRole = &model.UserAppRole{
			UserID:    user.ID,
			AppID:     app.ID,
			Role:      model.AppRole(claims.Role),
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.userAppRoleRepo.Create(ctx, userAppRole); err != nil {
			return nil, fmt.Errorf("failed to assign role: %w", err)
		}
	}

	appRoles, _ := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if appRoles == nil {
		appRoles = make(map[string]string)
	}

	user.LastLogin = &now
	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}

	tokenSet, err := s.tokenService.GenerateTokenSet(
		user, app, string(userAppRole.Role),
		"openid email profile offline_access",
		appRoles, "", now.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Log invite acceptance
	s.logSecurityEvent(ctx, model.SecurityEventInviteAccepted, &user.ID, &app.ID, true, map[string]interface{}{
		"email": user.Email,
	})

	return &dto.LoginResponse{
		AccessToken:  tokenSet.AccessToken,
		RefreshToken: tokenSet.RefreshToken,
		IDToken:      tokenSet.IDToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokenSet.ExpiresIn,
		UserID:       user.ID,
		App:          &dto.AppResponse{ID: app.ID, Name: app.Name, ClientID: app.ClientID},
		Roles:        []string{string(userAppRole.Role)},
		AppRoles:     appRoles,
	}, nil
}

// logSecurityEvent logs a security event if the audit repository is configured
func (s *authService) logSecurityEvent(ctx context.Context, eventType model.SecurityEventType, userID *uint, appID *uint, success bool, details map[string]interface{}) {
	if s.auditRepo == nil {
		return
	}

	// RFC-008: build via the shared helper so the correlation ID from the
	// request context is stamped on login/lockout/etc. audit rows.
	log := newSecurityAuditLog(ctx, eventType, userID, appID, "", "", success, details)

	// Fire and forget - don't let audit logging failure affect the main operation
	_ = s.auditRepo.Create(ctx, log)
}
