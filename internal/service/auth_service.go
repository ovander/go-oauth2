package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/socrate-auth/go-oauth/internal/dto"
	"github.com/socrate-auth/go-oauth/internal/model"
	"github.com/socrate-auth/go-oauth/internal/repository"
	"github.com/socrate-auth/go-oauth/internal/shared/auth"
)

var (
	ErrInvalidToken = errors.New("invalid or expired token")
)

type AuthService interface {
	Signup(ctx context.Context, req dto.SignupRequest) (*model.User, string, error)
	VerifyEmail(ctx context.Context, token string) error
	Login(ctx context.Context, req dto.LoginRequest) (*dto.LoginResponse, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error)
	Logout(ctx context.Context, userID uint) error
	RequestPasswordReset(ctx context.Context, email string) (string, error)
	ResetPassword(ctx context.Context, token, newPassword string) error
	ValidateInviteToken(ctx context.Context, token string) (*dto.InviteValidationResponse, error)
	AcceptInvite(ctx context.Context, token, password string) (*dto.LoginResponse, error)
}

type authService struct {
	userRepo          repository.UserRepository
	appRepo           repository.AppRepository
	userAppRoleRepo   repository.UserAppRoleRepository
	tokenService      *auth.TokenService
	maxFailedAttempts int
	lockoutDuration   time.Duration
}

type AuthServiceConfig struct {
	MaxFailedAttempts int
	LockoutDuration   time.Duration
}

func NewAuthService(
	userRepo repository.UserRepository,
	appRepo repository.AppRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	tokenService *auth.TokenService,
	config AuthServiceConfig,
) AuthService {
	return &authService{
		userRepo:          userRepo,
		appRepo:           appRepo,
		userAppRoleRepo:   userAppRoleRepo,
		tokenService:      tokenService,
		maxFailedAttempts: config.MaxFailedAttempts,
		lockoutDuration:   config.LockoutDuration,
	}
}

func (s *authService) Signup(ctx context.Context, req dto.SignupRequest) (*model.User, string, error) {
	if err := auth.ValidatePassword(req.Password); err != nil {
		return nil, "", err
	}

	existing, _ := s.userRepo.FindByEmail(ctx, req.Email)
	if existing != nil {
		return nil, "", ErrEmailAlreadyExists
	}

	app, err := s.appRepo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, "", ErrAppNotFound
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, "", err
	}

	user := &model.User{
		Email:          req.Email,
		Name:           req.Name,
		HashedPassword: hashedPassword,
		Role:           model.UserRoleUser,
		IsVerified:     false,
		TokenVersion:   1,
		Source:         "signup",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, "", err
	}

	userAppRole := &model.UserAppRole{
		UserID:    user.ID,
		AppID:     app.ID,
		Role:      model.AppRoleUser,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.userAppRoleRepo.Create(ctx, userAppRole); err != nil {
		return nil, "", err
	}

	verifyToken, err := s.tokenService.GenerateEmailVerificationToken(user.Email, user.ID)
	if err != nil {
		return nil, "", err
	}

	return user, verifyToken, nil
}

func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	claims, err := s.tokenService.VerifyEmailToken(token)
	if err != nil {
		return ErrInvalidToken
	}

	if claims.Type != "email_verification" || claims.Action != "verify" {
		return ErrInvalidToken
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return ErrUserNotFound
	}

	user.IsVerified = true
	now := time.Now()
	user.ConfirmedAt = &now
	user.UpdatedAt = now

	return s.userRepo.Update(ctx, user)
}

func (s *authService) Login(ctx context.Context, req dto.LoginRequest) (*dto.LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if user.IsLocked() {
		return nil, ErrAccountLocked
	}

	if !auth.CheckPassword(req.Password, user.HashedPassword) {
		s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID)
		user, _ = s.userRepo.FindByID(ctx, user.ID)
		if user.FailedLoginAttempts >= s.maxFailedAttempts {
			lockUntil := time.Now().Add(s.lockoutDuration)
			s.userRepo.LockAccount(ctx, user.ID, &lockUntil)
			return nil, ErrAccountLocked
		}
		return nil, ErrInvalidCredentials
	}

	if !user.IsVerified {
		return nil, ErrUserNotVerified
	}

	app, err := s.appRepo.FindByClientID(ctx, req.AppClientID)
	if err != nil {
		return nil, ErrAppNotFound
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		return nil, ErrRoleNotFound
	}

	appRoles, err := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if err != nil {
		appRoles = make(map[string]string)
	}

	s.userRepo.ResetFailedLoginAttempts(ctx, user.ID)
	now := time.Now()
	user.LastLogin = &now
	user.LastLoginAttempt = &now
	user.UpdatedAt = now
	s.userRepo.Update(ctx, user)

	tokenSet, err := s.tokenService.GenerateTokenSet(
		user, app, string(userAppRole.Role),
		"openid email profile offline_access",
		appRoles, "", now.Unix(),
	)
	if err != nil {
		return nil, err
	}

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

func (s *authService) RefreshTokens(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error) {
	claims, err := s.tokenService.VerifyRefreshToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return nil, ErrUserNotFound
	}

	if user.TokenVersion != claims.Ver {
		return nil, ErrInvalidToken
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrAppNotFound
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		return nil, ErrRoleNotFound
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
		return nil, err
	}

	return &dto.RefreshResponse{
		AccessToken:  tokenSet.AccessToken,
		RefreshToken: tokenSet.RefreshToken,
		IDToken:      tokenSet.IDToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokenSet.ExpiresIn,
	}, nil
}

func (s *authService) Logout(ctx context.Context, userID uint) error {
	return s.userRepo.IncrementTokenVersion(ctx, userID)
}

func (s *authService) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return "", nil // Don't reveal if email exists
	}
	return s.tokenService.GeneratePasswordResetToken(user.Email, user.ID)
}

func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	claims, err := s.tokenService.VerifyEmailToken(token)
	if err != nil {
		return ErrInvalidToken
	}

	if claims.Type != "password_reset" || claims.Action != "reset" {
		return ErrInvalidToken
	}

	if err := auth.ValidatePassword(newPassword); err != nil {
		return err
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return ErrUserNotFound
	}

	hashedPassword, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.HashedPassword = hashedPassword
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	return s.userRepo.IncrementTokenVersion(ctx, user.ID)
}

func (s *authService) ValidateInviteToken(ctx context.Context, token string) (*dto.InviteValidationResponse, error) {
	claims, err := s.tokenService.VerifyInviteToken(token)
	if err != nil {
		return &dto.InviteValidationResponse{Valid: false}, nil
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

func (s *authService) AcceptInvite(ctx context.Context, token, password string) (*dto.LoginResponse, error) {
	claims, err := s.tokenService.VerifyInviteToken(token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if err := auth.ValidatePassword(password); err != nil {
		return nil, err
	}

	user, err := s.userRepo.FindByEmail(ctx, claims.Email)
	if err != nil {
		hashedPassword, err := auth.HashPassword(password)
		if err != nil {
			return nil, err
		}

		now := time.Now()
		user = &model.User{
			Email:          claims.Email,
			Name:           claims.Email,
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
			return nil, err
		}
	} else {
		hashedPassword, err := auth.HashPassword(password)
		if err != nil {
			return nil, err
		}

		now := time.Now()
		user.HashedPassword = hashedPassword
		user.IsVerified = true
		user.ConfirmedAt = &now
		user.UpdatedAt = now

		if err := s.userRepo.Update(ctx, user); err != nil {
			return nil, err
		}
	}

	app, err := s.appRepo.FindByID(ctx, claims.AppID)
	if err != nil {
		return nil, ErrAppNotFound
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		userAppRole = &model.UserAppRole{
			UserID:    user.ID,
			AppID:     app.ID,
			Role:      model.AppRole(claims.Role),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := s.userAppRoleRepo.Create(ctx, userAppRole); err != nil {
			return nil, err
		}
	}

	appRoles, _ := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if appRoles == nil {
		appRoles = make(map[string]string)
	}

	now := time.Now()
	user.LastLogin = &now
	s.userRepo.Update(ctx, user)

	tokenSet, err := s.tokenService.GenerateTokenSet(
		user, app, string(userAppRole.Role),
		"openid email profile offline_access",
		appRoles, "", now.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

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
