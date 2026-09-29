package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/hooks"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/logger"
)

const (
	// magicLinkTTL is the maximum lifetime of a magic-link token.
	// 15 minutes is the industry ceiling for passwordless email tokens.
	magicLinkTTL = 15 * time.Minute

	// magicLinkRateWindow is the sliding window used to enforce per-address
	// rate limiting.  We allow at most magicLinkRateMax requests per address
	// per app within this window.
	magicLinkRateWindow = 1 * time.Hour

	// magicLinkRateMax is the maximum number of magic-link tokens that may be
	// outstanding (unused) for the same (email, app) pair within the rate window.
	magicLinkRateMax = 5

	// magicLinkRawBytes is the size of the raw random token before hex encoding.
	// 32 bytes → 256 bits of entropy; hex-encoded to 64 ASCII chars.
	magicLinkRawBytes = 32
)

// ErrMagicLinkRateLimited is returned when too many tokens have been requested
// for the same (email, app) pair within the rate window.
var ErrMagicLinkRateLimited = errors.New("too many magic link requests, please try again later")

// MagicLinkService handles passwordless magic-link authentication.
type MagicLinkService interface {
	// RequestMagicLink generates and emails a single-use login token.
	//
	// app must be the authenticated service account's app, resolved and validated
	// by ServiceAccountMiddleware before this method is called.  The caller never
	// needs to pass a client_id — the app identity is already proven.
	//
	// Always returns the same opaque result regardless of whether the user email
	// is registered, to prevent enumeration.  rawToken is non-empty only in
	// development mode or when emailService is nil, so callers can exercise the
	// full verify flow without a real mail server.
	RequestMagicLink(ctx context.Context, email string, app *model.App) (rawToken string, err error)

	// VerifyMagicLink exchanges a raw token for a full token set.
	// The token must not be used or expired, and the user must be active.
	// client_id is required here because this endpoint is public — the app
	// context is not available from a service account token at this stage.
	VerifyMagicLink(ctx context.Context, req dto.MagicLinkVerifyRequest) (*dto.LoginResponse, error)
}

type magicLinkService struct {
	magicLinkRepo   repository.MagicLinkRepository
	userRepo        repository.UserRepository
	appRepo         repository.AppRepository // used only in VerifyMagicLink
	userAppRoleRepo repository.UserAppRoleRepository
	tokenService    *auth.TokenService
	emailService    EmailService
	issuer          string
	environment     string
}

// NewMagicLinkService creates a new MagicLinkService.
// emailService may be nil in tests; in that case the raw token is returned
// directly so callers can exercise the full verify flow without SMTP.
func NewMagicLinkService(
	magicLinkRepo repository.MagicLinkRepository,
	userRepo repository.UserRepository,
	appRepo repository.AppRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
	tokenService *auth.TokenService,
	emailService EmailService,
	issuer string,
	environment string,
) MagicLinkService {
	return &magicLinkService{
		magicLinkRepo:   magicLinkRepo,
		userRepo:        userRepo,
		appRepo:         appRepo,
		userAppRoleRepo: userAppRoleRepo,
		tokenService:    tokenService,
		emailService:    emailService,
		issuer:          issuer,
		environment:     environment,
	}
}

// RequestMagicLink implements MagicLinkService.
//
// app is the service account's app, already validated by ServiceAccountMiddleware.
// The caller is the app backend — it has already decided the user should receive
// a magic link.  We still silently swallow unknown-user / no-role cases to avoid
// leaking that information back to the backend via a different code path.
func (s *magicLinkService) RequestMagicLink(ctx context.Context, email string, app *model.App) (string, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		logger.Logger.WithFields(logger.Fields{
			"email":  email,
			"app_id": app.ID,
		}).Debug("magic link requested for unknown email — silently ignored")
		return "", nil
	}

	if user.IsLocked() {
		logger.Logger.WithFields(logger.Fields{
			"user_id": user.ID,
			"app_id":  app.ID,
		}).Debug("magic link requested for locked account — silently ignored")
		return "", nil
	}

	// Confirm user has access to this app.
	_, err = s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		logger.Logger.WithFields(logger.Fields{
			"user_id": user.ID,
			"app_id":  app.ID,
		}).Debug("magic link requested but user has no role in app — silently ignored")
		return "", nil
	}

	// Per-address rate limit: at most magicLinkRateMax outstanding tokens
	// within magicLinkRateWindow.
	since := time.Now().Add(-magicLinkRateWindow)
	count, err := s.magicLinkRepo.CountUnusedByEmail(ctx, email, app.ID, since)
	if err != nil {
		return "", fmt.Errorf("rate limit check failed: %w", err)
	}
	if count >= magicLinkRateMax {
		return "", ErrMagicLinkRateLimited
	}

	// Generate cryptographically-random raw token.
	rawBytes := make([]byte, magicLinkRawBytes)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", fmt.Errorf("failed to generate magic link token: %w", err)
	}
	rawToken := hex.EncodeToString(rawBytes)

	// Hash the token; only the hash is persisted.
	tokenHash := hashMagicToken(rawToken)

	now := time.Now()
	record := &model.MagicLinkToken{
		TokenHash: tokenHash,
		UserID:    user.ID,
		AppID:     app.ID,
		Email:     email,
		ExpiresAt: now.Add(magicLinkTTL),
		CreatedAt: now,
	}
	if err := s.magicLinkRepo.Create(ctx, record); err != nil {
		return "", fmt.Errorf("failed to persist magic link token: %w", err)
	}

	// Build the magic URL.  This points at the OAuth/OIDC port (8080), not
	// the admin port, since it is a user-facing authentication action.
	// The verify endpoint needs client_id so the user's browser can identify
	// the app without a service account token.
	magicURL := s.issuer + "/api/auth/magic-link/verify?token=" + rawToken + "&client_id=" + app.ClientID

	// In dev mode or when emailService is absent, return the raw token to the
	// caller (handler exposes it in the response body only in dev mode).
	if s.emailService == nil {
		logger.Logger.WithFields(logger.Fields{
			"user_id":   user.ID,
			"app_id":    app.ID,
			"magic_url": magicURL,
		}).Info("[NO-EMAIL] magic link generated")
		return rawToken, nil
	}

	// Send the magic-link email.  Failure is logged but not propagated so that
	// transient SMTP errors do not leak enumeration information.
	if err := s.emailService.SendMagicLinkEmail(user.Email, user.Name, app.Name, magicURL); err != nil {
		logger.Logger.WithFields(logger.Fields{
			"user_id": user.ID,
			"app_id":  app.ID,
			"error":   err.Error(),
		}).Error("failed to send magic link email")
	}

	// In development environment, return the raw token so callers can test
	// the verify flow without a real mail server.
	if s.environment == "development" || s.environment == "dev" {
		return rawToken, nil
	}

	return "", nil
}

// VerifyMagicLink implements MagicLinkService.
func (s *magicLinkService) VerifyMagicLink(ctx context.Context, req dto.MagicLinkVerifyRequest) (*dto.LoginResponse, error) {
	if req.Token == "" {
		return nil, ErrInvalidToken
	}

	tokenHash := hashMagicToken(req.Token)

	record, err := s.magicLinkRepo.FindByTokenHash(ctx, tokenHash)
	if err != nil {
		// Map not-found to a generic invalid-token error so callers cannot
		// distinguish between a wrong token and a used/expired one.
		return nil, ErrInvalidToken
	}

	if record.Used {
		return nil, ErrTokenAlreadyUsed
	}

	if record.IsExpired() {
		return nil, fmt.Errorf("%w: magic link has expired", ErrInvalidToken)
	}

	// Atomically mark the token used.  Under concurrent requests the UPDATE
	// WHERE used=false guard ensures only the first caller succeeds.
	if err := s.magicLinkRepo.MarkUsed(ctx, record.ID); err != nil {
		if errors.Is(err, repository.ErrMagicLinkAlreadyUsed) {
			return nil, ErrTokenAlreadyUsed
		}
		return nil, fmt.Errorf("failed to consume magic link token: %w", err)
	}

	// Validate the app context from the request.
	app, err := s.appRepo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: client_id=%s", ErrAppNotFound, req.ClientID)
	}

	// Cross-check: the token was issued for this app.
	if record.AppID != app.ID {
		return nil, fmt.Errorf("%w: token app mismatch", ErrInvalidToken)
	}

	user, err := s.userRepo.FindByID(ctx, record.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: user_id=%d", ErrUserNotFound, record.UserID)
	}

	if user.IsLocked() {
		return nil, fmt.Errorf("%w: try again later", ErrAccountLocked)
	}

	userAppRole, err := s.userAppRoleRepo.FindByUserAndApp(ctx, user.ID, app.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: user has no access to app", ErrRoleNotFound)
	}

	appRoles, err := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if err != nil {
		appRoles = make(map[string]string)
	}

	// Update last login timestamp.
	now := time.Now()
	user.LastLogin = &now
	user.UpdatedAt = now
	_ = s.userRepo.Update(ctx, user) // best-effort; don't fail the login

	if err := hooks.RunBeforeTokenIssue(ctx, &hooks.TokenIssue{User: user, App: app, Grant: "magic_link"}); err != nil {
		return nil, err
	}
	tokenSet, err := s.tokenService.GenerateTokenSet(
		user, app, string(userAppRole.Role),
		"openid email profile offline_access",
		appRoles, "", now.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	logger.Logger.WithFields(logger.Fields{
		"user_id": user.ID,
		"app_id":  app.ID,
	}).Info("✅ Magic link verified — tokens issued")

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

// hashMagicToken returns the lowercase hex-encoded SHA-256 digest of a raw token.
func hashMagicToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
