package service

import (
	"context"
	"fmt"
	"strconv"
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
	RequestPasswordReset(ctx context.Context, email string) (string, error)
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID uint, currentPassword, newPassword string) error
	ValidateInviteToken(ctx context.Context, token string) (*dto.InviteValidationResponse, error)
	AcceptInvite(ctx context.Context, token, name, password string) (*dto.LoginResponse, error)
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

	verifyToken, err := s.tokenService.GenerateEmailVerificationToken(user.Email, user.ID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Send verification email
	if s.emailService != nil {
		if err := s.emailService.SendVerificationEmail(user.Email, user.Name, verifyToken); err != nil {
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

	// Check if token has already been used (single-use enforcement)
	if s.usedTokenRepo != nil {
		used, err := s.usedTokenRepo.IsUsed(ctx, claims.ID)
		if err != nil {
			return fmt.Errorf("failed to check token usage: %w", err)
		}
		if used {
			return ErrTokenAlreadyUsed
		}
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid subject", ErrInvalidToken)
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	// Mark token as used before making changes
	if s.usedTokenRepo != nil {
		if err := s.usedTokenRepo.MarkAsUsed(ctx, claims.ID, claims.Type, uint(userID), claims.ExpiresAt.Time); err != nil {
			return fmt.Errorf("failed to mark token as used: %w", err)
		}
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
			// Log error but continue
		}
		user, _ = s.userRepo.FindByID(ctx, user.ID)
		if user.FailedLoginAttempts >= s.maxFailedAttempts {
			lockUntil := time.Now().Add(s.lockoutDuration)
			if err := s.userRepo.LockAccount(ctx, user.ID, &lockUntil); err != nil {
				// Log error but continue
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
		// Log error but continue
	}
	now := time.Now()
	user.LastLogin = &now
	user.LastLoginAttempt = &now
	user.UpdatedAt = now
	if err := s.userRepo.Update(ctx, user); err != nil {
		// Log error but continue
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
			// Log error but continue
		}
		user, _ = s.userRepo.FindByID(ctx, user.ID)
		if user.FailedLoginAttempts >= s.maxFailedAttempts {
			lockUntil := time.Now().Add(s.lockoutDuration)
			if err := s.userRepo.LockAccount(ctx, user.ID, &lockUntil); err != nil {
				// Log error but continue
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

	// Reset failed attempts and update last login
	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
		// Log error but continue
	}
	now := time.Now()
	user.LastLogin = &now
	user.LastLoginAttempt = &now
	user.UpdatedAt = now
	if err := s.userRepo.Update(ctx, user); err != nil {
		// Log error but continue
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

// RequestPasswordReset initiates a password reset
func (s *authService) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// Don't reveal if email exists - return empty string without error
		return "", nil
	}

	token, err := s.tokenService.GeneratePasswordResetToken(user.Email, user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Send password reset email
	if s.emailService != nil {
		if err := s.emailService.SendPasswordResetEmail(user.Email, user.Name, token); err != nil {
			s.logSecurityEvent(ctx, model.SecurityEventEmailSendFailed, &user.ID, nil, false, map[string]interface{}{
				"email": user.Email,
				"type":  "password_reset",
				"error": err.Error(),
			})
		}
	}

	// Log password reset request
	s.logSecurityEvent(ctx, model.SecurityEventPasswordResetReq, &user.ID, nil, true, map[string]interface{}{
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

	// Check if token has already been used (single-use enforcement)
	if s.usedTokenRepo != nil {
		used, err := s.usedTokenRepo.IsUsed(ctx, claims.ID)
		if err != nil {
			return fmt.Errorf("failed to check token usage: %w", err)
		}
		if used {
			return ErrTokenAlreadyUsed
		}
	}

	if err := auth.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid subject", ErrInvalidToken)
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	hashedPassword, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Mark token as used before making changes
	if s.usedTokenRepo != nil {
		if err := s.usedTokenRepo.MarkAsUsed(ctx, claims.ID, claims.Type, uint(userID), claims.ExpiresAt.Time); err != nil {
			return fmt.Errorf("failed to mark token as used: %w", err)
		}
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

	// Check if token has already been used
	if s.usedTokenRepo != nil {
		used, err := s.usedTokenRepo.IsUsed(ctx, claims.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check token usage: %w", err)
		}
		if used {
			return nil, ErrTokenAlreadyUsed
		}
	}

	if err := auth.ValidatePassword(password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Mark token as used before making changes
	if s.usedTokenRepo != nil {
		if err := s.usedTokenRepo.MarkAsUsed(ctx, claims.ID, claims.Type, 0, claims.ExpiresAt.Time); err != nil {
			return nil, fmt.Errorf("failed to mark token as used: %w", err)
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
		// Log error but continue
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

	severity := model.GetSeverityForEvent(eventType, success)

	log := &model.SecurityAuditLog{
		UserID:    userID,
		AppID:     appID,
		EventType: eventType,
		Severity:  severity,
		Success:   success,
		Details:   details,
		CreatedAt: time.Now(),
	}

	// Fire and forget - don't let audit logging failure affect the main operation
	_ = s.auditRepo.Create(ctx, log)
}
