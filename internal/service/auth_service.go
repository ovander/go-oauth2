package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/hooks"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/logger"
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
	// AuthenticateAccount verifies a user's own credentials for Socrate's hosted
	// account page (ACCOUNT_SECURITY_PAGE). It issues no token and needs no
	// application membership.
	AuthenticateAccount(ctx context.Context, email, password, mfaCode string) (*model.User, error)
	// WithMFA enables login step-up: when set, a user with MFA enabled must
	// present a valid TOTP code (LoginRequest.MFACode) to complete login.
	// Optional and nil-safe — without it, login behaviour is unchanged. Returns
	// the receiver for chaining. RFC-011 / EPIC-9.
	WithMFA(mfa MFAService) AuthService
}

// RefreshGranter performs a refresh-token grant using the single hardened
// implementation (rotation + single-use/replay detection + token-family
// revocation + DPoP binding) that also backs the /oauth/token refresh grant.
// The bearer refresh endpoint (POST /api/auth/refresh) delegates to it so the
// platform has exactly one refresh code path. The client is identified by the
// refresh token's own audience claim.
type RefreshGranter interface {
	RefreshFromBearer(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error)
}

// Reauthenticator re-verifies an already-identified admin's credentials and
// issues a fresh-auth_time access token for step-up (POST /api/admin/elevate),
// so the most destructive admin routes (gated by middleware.RequireFreshAuth)
// can require a recent authentication without a full logout/login cycle.
type Reauthenticator interface {
	ReAuthenticate(ctx context.Context, userID uint, password, mfaCode string) (*dto.LoginResponse, error)
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
	adminMFAPolicy    string     // "off" (default) | "observe" | "enforce"
	// refreshGranter is the single hardened refresh implementation that the
	// bearer refresh endpoint delegates to. Wired by bootstrap via
	// SetRefreshGranter once the OAuth service is constructed.
	refreshGranter RefreshGranter
	// adminAppSignIn refuses or audits a Socrate admin signing in to an
	// application that is not an operator console (ADMIN_APP_SIGNIN_POLICY).
	adminAppSignIn AdminAppSignInPolicy
	// lockoutSourceMode and loginFailures implement LOCKOUT_SOURCE_MODE
	// (#403): failed sign-ins counted per account and source.
	lockoutSourceMode string
	loginFailures     repository.LoginSourceFailureRepository
}

// SetLockoutSourcePolicy sets LOCKOUT_SOURCE_MODE (#403) and its store:
//
//   - "off": the account-wide lock, as before.
//   - "observe": the account-wide lock, and failures also counted per source,
//     with the source's count in the audit details (and source_would_lock
//     when enforce would lock it).
//   - "enforce": failures counted per account and source only. Reaching the
//     limit locks that source out of that account for the lockout duration;
//     the owner signing in from elsewhere is unaffected. A lock already on the
//     account (an admin block, or one set before enforce) still applies.
//
// A nil store leaves the mode off.
func (s *authService) SetLockoutSourcePolicy(mode string, failures repository.LoginSourceFailureRepository) {
	if failures == nil {
		mode = lockoutSourceOff
	}
	s.lockoutSourceMode, s.loginFailures = mode, failures
}

const (
	lockoutSourceOff     = "off"
	lockoutSourceObserve = "observe"
	lockoutSourceEnforce = "enforce"
)

func (s *authService) countsPerSource() bool {
	return s.loginFailures != nil && (s.lockoutSourceMode == lockoutSourceObserve || s.lockoutSourceMode == lockoutSourceEnforce)
}

// lockedOut reports whether the account is locked for this sign-in: by its
// account-wide lock, or (LOCKOUT_SOURCE_MODE=enforce) by a lock on the
// request's source. scope is "account" or "source". A store error counts as
// locked (fail closed).
func (s *authService) lockedOut(ctx context.Context, user *model.User) (locked bool, scope string) {
	if user.IsLocked() {
		return true, "account"
	}
	if s.lockoutSourceMode != lockoutSourceEnforce || s.loginFailures == nil {
		return false, ""
	}
	until, err := s.loginFailures.LockedUntil(ctx, user.ID, loginSource(ctx))
	if err != nil {
		logger.FromContext(ctx).Errorf("auth: could not read the source lock of user %d, refusing: %v", user.ID, err)
		return true, "source"
	}
	return until != nil, "source"
}

// resetFailedAttempts forgets the failed attempts after a complete sign-in:
// the account's counter, and the request source's count when it is kept.
func (s *authService) resetFailedAttempts(ctx context.Context, userID uint) error {
	if s.countsPerSource() {
		if err := s.loginFailures.Reset(ctx, userID, loginSource(ctx)); err != nil {
			logger.FromContext(ctx).Warnf("auth: could not reset the source failures of user %d: %v", userID, err)
		}
	}
	return s.userRepo.ResetFailedLoginAttempts(ctx, userID)
}

// SetRefreshGranter wires the single hardened refresh path so that
// /api/auth/refresh and /oauth/token share one rotation/replay/DPoP-enforcing
// implementation. Bootstrap calls this after the OAuth service is built.
func (s *authService) SetRefreshGranter(g RefreshGranter) { s.refreshGranter = g }

// SetAdminAppSignInPolicy wires ADMIN_APP_SIGNIN_POLICY into the hosted login.
func (s *authService) SetAdminAppSignInPolicy(p AdminAppSignInPolicy) { s.adminAppSignIn = p }

// checkAdminAppSignIn applies ADMIN_APP_SIGNIN_POLICY to a Socrate admin
// signing in to app without a membership: observe audits it, enforce refuses
// it with ErrAdminAppSignInRefused.
func (s *authService) checkAdminAppSignIn(ctx context.Context, user *model.User, app *model.App, path string) error {
	if !s.adminAppSignIn.outsideConsoles(user, app) {
		return nil
	}
	refused := s.adminAppSignIn.refuses()
	s.logSecurityEvent(ctx, model.SecurityEventAdminAppSignIn, &user.ID, &app.ID, !refused,
		s.adminAppSignIn.adminAppSignInDetails(user, app, path))
	if refused {
		return ErrAdminAppSignInRefused
	}
	return nil
}

// checkMagicLinkSignIn implements MagicLinkSignInPolicy: a Socrate admin
// signing in with a magic link gets the admin MFA-enrollment policy, as on the
// password paths. ADMIN_APP_SIGNIN_POLICY does not apply: it covers an admin
// signing in to an app without a membership, and a magic link always requires
// one (VerifyMagicLink checks the user's role in the app), so a member admin
// signs in as with a password.
func (s *authService) checkMagicLinkSignIn(ctx context.Context, user *model.User, _ *model.App) error {
	if !user.IsGlobalAdmin() {
		return nil
	}
	return s.enforceAdminMFAPolicy(ctx, user, "magic_link")
}

// enforceAdminMFAPolicy applies the admin-enrollment MFA policy when a Socrate
// admin or superadmin signs in, on any login path (loginType is audited). It is
// a no-op when the policy is off or the admin already has MFA enrolled.
// Otherwise it audits the gap and, under "enforce", denies login with
// ErrMFAEnrollmentRequired (the admin must enroll before they can log in).
func (s *authService) enforceAdminMFAPolicy(ctx context.Context, user *model.User, loginType string) error {
	if user.MFAEnabled {
		return nil
	}
	switch s.adminMFAPolicy {
	case MFAPolicyObserve:
		s.logSecurityEvent(ctx, model.SecurityEventMFAPolicyViolation, &user.ID, nil, true, map[string]interface{}{
			"email":      user.Email,
			"login_type": loginType,
			"policy":     MFAPolicyObserve,
		})
		return nil
	case MFAPolicyEnforce:
		s.logSecurityEvent(ctx, model.SecurityEventMFAPolicyViolation, &user.ID, nil, false, map[string]interface{}{
			"email":      user.Email,
			"login_type": loginType,
			"policy":     MFAPolicyEnforce,
		})
		return ErrMFAEnrollmentRequired
	default: // MFAPolicyOff / unset
		return nil
	}
}

// WithMFA wires the MFA verifier for login step-up and returns the receiver.
func (s *authService) WithMFA(mfa MFAService) AuthService {
	s.mfa = mfa
	return s
}

// stepUpMFA applies login step-up after the password has been verified. It is a
// no-op when step-up is not configured or the user has not enabled MFA.
// Otherwise an empty code yields ErrMFARequired (the client should prompt for a
// code and retry). The code may be a TOTP code or a one-time recovery code; a
// value that is neither yields ErrMFAInvalidCode. A redeemed recovery code is
// consumed and audited.
//
// A wrong code counts as a failed sign-in attempt, on the same per-account
// counter and lockout as a wrong password (the counter is reset only by a
// complete sign-in): once it reaches the limit the account is locked and
// ErrAccountLocked is returned. A failure to check the code (an error other
// than ErrMFAInvalidCode from the verifier) is refused without counting. A
// locked account is refused before any code is checked.
func (s *authService) stepUpMFA(ctx context.Context, user *model.User, code string) error {
	if s.mfa == nil || !user.MFAEnabled {
		return nil
	}
	if locked, _ := s.lockedOut(ctx, user); locked {
		return fmt.Errorf("%w: try again later", ErrAccountLocked)
	}
	if strings.TrimSpace(code) == "" {
		return ErrMFARequired
	}
	// A valid TOTP code is the common path.
	verifyErr := s.mfa.Verify(ctx, user.ID, code)
	if verifyErr == nil {
		return nil
	}
	// Otherwise fall back to a one-time recovery code.
	used, err := s.mfa.RedeemRecoveryCode(ctx, user.ID, code)
	if err != nil {
		logger.FromContext(ctx).Warnf("auth: recovery-code redemption error for user %d: %v", user.ID, err)
		return ErrMFAInvalidCode
	}
	if used {
		s.logSecurityEvent(ctx, model.SecurityEventMFARecoveryUsed, &user.ID, nil, true, map[string]interface{}{
			"email": user.Email,
		})
		return nil
	}
	// Count only a code that was checked and is wrong, not a failure to check
	// it (an unreadable secret, a storage error): that would lock accounts for
	// an operator problem.
	if !errors.Is(verifyErr, ErrMFAInvalidCode) {
		logger.FromContext(ctx).Warnf("auth: TOTP verification error for user %d: %v", user.ID, verifyErr)
		return ErrMFAInvalidCode
	}
	if locked, counts := s.countFailedAttempt(ctx, user); locked {
		details := map[string]interface{}{"email": user.Email, "reason": "mfa_invalid"}
		for k, v := range counts {
			details[k] = v
		}
		s.logSecurityEvent(ctx, model.SecurityEventAccountLocked, &user.ID, nil, false, details)
		return ErrAccountLocked
	}
	return ErrMFAInvalidCode
}

// loginAuthnContext derives the RFC 8176 amr / acr for an interactive password
// login. The password is always verified (`pwd`); when the user completed MFA
// step-up a second factor was used (`otp`, `mfa`) and the context class is
// "mfa" rather than the single-factor "pwd". Stamped on the issued access and
// ID tokens so resource servers can make their own assurance/step-up decisions
// (RFC-001 canonical claim set).
func loginAuthnContext(mfaUsed bool) (amr []string, acr string) {
	if mfaUsed {
		return []string{"pwd", "otp", "mfa"}, "mfa"
	}
	return []string{"pwd"}, "pwd"
}

// MFA admin-enrollment policy modes. "off" leaves admin login unchanged;
// "observe" allows an admin without MFA but audits it; "enforce" denies login
// until the admin enrolls. (Observe→enforce rollout, RFC-011.)
const (
	MFAPolicyOff     = "off"
	MFAPolicyObserve = "observe"
	MFAPolicyEnforce = "enforce"
)

// AuthServiceConfig holds auth service configuration
type AuthServiceConfig struct {
	MaxFailedAttempts int
	LockoutDuration   time.Duration
	// AdminMFAPolicy is one of "off" (default), "observe", or "enforce" and
	// governs whether admin-portal login requires MFA enrollment.
	AdminMFAPolicy string
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
	}).Debug("✅ Auth service initialized")

	return &authService{
		userRepo:          userRepo,
		appRepo:           appRepo,
		userAppRoleRepo:   userAppRoleRepo,
		usedTokenRepo:     nil, // Optional - will skip single-use check if nil
		auditRepo:         nil, // Optional - will skip audit logging if nil
		tokenService:      tokenService,
		maxFailedAttempts: config.MaxFailedAttempts,
		lockoutDuration:   config.LockoutDuration,
		adminMFAPolicy:    config.AdminMFAPolicy,
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
	}).Debug("✅ Auth service initialized")

	return &authService{
		userRepo:          userRepo,
		appRepo:           appRepo,
		userAppRoleRepo:   userAppRoleRepo,
		usedTokenRepo:     usedTokenRepo,
		auditRepo:         nil,
		tokenService:      tokenService,
		maxFailedAttempts: config.MaxFailedAttempts,
		lockoutDuration:   config.LockoutDuration,
		adminMFAPolicy:    config.AdminMFAPolicy,
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
	}).Debug("✅ Auth service initialized")

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
		adminMFAPolicy:    config.AdminMFAPolicy,
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
	hooks.RunUserProvisioned(ctx, hooks.UserProvisioned{User: user, App: app, Source: "signup"})

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

	userID, err := strconv.ParseUint(claims.Subject, 10, strconv.IntSize)
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
		// L1 fix: an unknown email must not return faster than a known email
		// with a wrong password — pay the same bcrypt cost on both paths so
		// response timing cannot be used to enumerate accounts.
		auth.CheckDummyPassword()
		return nil, ErrInvalidCredentials
	}

	if err := s.checkPasswordWithLockout(ctx, user, req.Password, ""); err != nil {
		return nil, err
	}

	if !user.IsVerified {
		return nil, fmt.Errorf("%w: please verify your email first", ErrUserNotVerified)
	}

	// Admin MFA-enrollment policy (RFC-011, HIGH-04): the consoles sign in
	// through this path (/oauth/authorize), not AdminLogin, so the policy must
	// apply here to every Socrate admin and superadmin.
	if user.IsGlobalAdmin() {
		if err := s.enforceAdminMFAPolicy(ctx, user, "password"); err != nil {
			return nil, err
		}
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
		// Global admins (admin/superadmin) may sign in to any app's hosted login
		// without an explicit per-app membership, consistent with
		// middleware.RequireAppAdmin. This is what lets a platform superadmin use
		// the first-party admin console (and any app) without being seeded as a
		// member of that client. Non-admins still require a membership row.
		if !user.IsGlobalAdmin() {
			return nil, fmt.Errorf("%w: user has no access to app", ErrRoleNotFound)
		}
		// ADMIN_APP_SIGNIN_POLICY: outside the operator consoles, an admin's
		// sign-in is audited (observe) or refused here, on the sign-in page.
		if err := s.checkAdminAppSignIn(ctx, user, app, "login"); err != nil {
			return nil, err
		}
		userAppRole = &model.UserAppRole{UserID: user.ID, AppID: app.ID, Role: model.AppRoleAdmin}
	}

	appRoles, err := s.userAppRoleRepo.GetUserRolesMap(ctx, user.ID)
	if err != nil {
		appRoles = make(map[string]string)
	}

	// Reset failed attempts and update last login
	if err := s.resetFailedAttempts(ctx, user.ID); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}
	// Only the sign-in times are written: user was loaded before the password
	// check, and a full-row save would undo a change made meanwhile.
	now := time.Now()
	user.LastLogin = &now
	user.LastLoginAttempt = &now
	user.UpdatedAt = now
	if err := s.userRepo.RecordLogin(ctx, user.ID, now, true); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}

	amr, acr := loginAuthnContext(user.MFAEnabled)
	if err := hooks.RunBeforeTokenIssue(ctx, &hooks.TokenIssue{User: user, App: app, Grant: "password", Scope: "openid email profile offline_access"}); err != nil {
		return nil, err
	}
	tokenSet, err := s.tokenService.GenerateTokenSetWithAuth(
		user, app, string(userAppRole.Role),
		"openid email profile offline_access",
		appRoles, "", now.Unix(), amr, acr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Log successful login
	s.logSecurityEvent(ctx, model.SecurityEventLoginSuccess, &user.ID, &app.ID, true, map[string]interface{}{
		"email": user.Email,
	})
	hooks.RunAfterLogin(ctx, hooks.Login{User: user, App: app, Method: "password", MFA: user.MFAEnabled})

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
		AuthTime:           now.Unix(),
		AMR:                amr,
		ACR:                acr,
	}, nil
}

// checkPasswordWithLockout refuses a locked account and checks the password.
// A wrong password counts as a failed attempt; reaching the limit locks the
// account. Both are audited. Shared by Login and AuthenticateAccount so every
// password check on behalf of a user counts towards the same lockout.
//
// A locked account does not reveal itself: its password is still checked, at
// the same cost as any attempt, and only the right password gets
// ErrAccountLocked (whoever typed it knows the account, and the owner learns
// why they cannot sign in). A wrong one gets ErrInvalidCredentials, exactly as
// an unknown email or another wrong password does, and is audited without
// counting towards the lock already in place.
func (s *authService) checkPasswordWithLockout(ctx context.Context, user *model.User, password, loginType string) error {
	if locked, scope := s.lockedOut(ctx, user); locked {
		// Both answers are audited. The right password on a locked account
		// is the one the SOC most needs to see: whoever typed it knows the
		// credential, while the lock may be there because of an attack.
		passwordOK := auth.CheckPassword(password, user.HashedPassword)
		details := map[string]interface{}{"email": user.Email, "account_locked": true, "password_verified": passwordOK}
		if scope == "source" {
			// The lock key, as the counting path records it: for IPv6 it is
			// the /64, which the row's ip_address alone does not show.
			details["lock_scope"] = "source"
			details["source"] = loginSource(ctx)
		}
		if loginType != "" {
			details["login_type"] = loginType
		}
		s.logSecurityEvent(ctx, model.SecurityEventLoginFailed, &user.ID, nil, false, details)
		if passwordOK {
			return fmt.Errorf("%w: try again later", ErrAccountLocked)
		}
		return ErrInvalidCredentials
	}
	if auth.CheckPassword(password, user.HashedPassword) {
		return nil
	}
	locked, counts := s.countFailedAttempt(ctx, user)
	details := map[string]interface{}{"email": user.Email}
	for k, v := range counts {
		details[k] = v
	}
	if loginType != "" {
		details["login_type"] = loginType
	}
	if locked {
		// Log account lockout
		s.logSecurityEvent(ctx, model.SecurityEventAccountLocked, &user.ID, nil, false, details)
		return ErrAccountLocked
	}
	// Log failed login attempt
	s.logSecurityEvent(ctx, model.SecurityEventLoginFailed, &user.ID, nil, false, details)
	return ErrInvalidCredentials
}

// countFailedAttempt records one failed sign-in attempt (a wrong password or a
// wrong second-factor code) and reports whether it locked the account, with
// the counts for the audit details.
//
// Under LOCKOUT_SOURCE_MODE=enforce the attempt is counted against the
// account and the request's source only, and reaching the limit locks that
// source out of the account (lock_scope "source"). Otherwise it is counted on
// the account, which is locked at the limit; observe also counts it per
// source and says whether enforce would lock the source. Persistence errors are
// logged and do not stop the caller, which refuses the attempt either way.
func (s *authService) countFailedAttempt(ctx context.Context, user *model.User) (bool, map[string]interface{}) {
	counts := map[string]interface{}{}
	sourceLocked, sourceCounted := false, false
	if s.countsPerSource() {
		source := loginSource(ctx)
		n, err := s.loginFailures.RecordFailure(ctx, user.ID, source, s.lockoutDuration)
		counts["source"] = source
		if err != nil {
			logger.FromContext(ctx).Errorf("auth: could not count a source failure of user %d: %v", user.ID, err)
			counts["source_store_error"] = true
		} else {
			sourceCounted = true
			counts["source_failed_attempts"] = n
		}
		if sourceCounted && n >= s.maxFailedAttempts {
			if s.lockoutSourceMode == lockoutSourceEnforce {
				if err := s.loginFailures.Lock(ctx, user.ID, source, time.Now().Add(s.lockoutDuration)); err != nil {
					logger.FromContext(ctx).Warnf("auth: could not lock source %s out of user %d: %v", source, user.ID, err)
				}
				sourceLocked = true
			} else {
				counts["source_would_lock"] = true
			}
		}
	}
	// Under enforce the source's count replaces the account's — unless it
	// could not be written: then the attempt counts on the account, as in off,
	// rather than not at all (fail closed).
	if s.lockoutSourceMode == lockoutSourceEnforce && s.loginFailures != nil && sourceCounted {
		if sourceLocked {
			counts["lock_scope"] = "source"
		}
		return sourceLocked, counts
	}
	locked, attempts := s.countAccountFailure(ctx, user)
	counts["failed_attempts"] = attempts
	return locked, counts
}

// countAccountFailure counts the attempt on the user's account-wide counter
// and locks the account for the lockout duration once it reaches the limit.
func (s *authService) countAccountFailure(ctx context.Context, user *model.User) (locked bool, attempts int) {
	if err := s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}
	attempts = user.FailedLoginAttempts + 1
	if refreshed, err := s.userRepo.FindByID(ctx, user.ID); err == nil && refreshed != nil {
		attempts = refreshed.FailedLoginAttempts
	}
	if attempts < s.maxFailedAttempts {
		return false, attempts
	}
	lockUntil := time.Now().Add(s.lockoutDuration)
	if err := s.userRepo.LockAccount(ctx, user.ID, &lockUntil); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}
	return true, attempts
}

// AuthenticateAccount verifies a user's own credentials for Socrate's hosted
// account page: the password, with the same lockout and audit as Login, then
// the second factor when the user has one (a TOTP or recovery code). It issues
// no token and checks no application membership.
//
// Socrate admins and superadmins are refused with ErrAccountPageAdmin, after
// their password is verified: they manage MFA in the admin console, where
// ADMIN_MFA_POLICY applies.
func (s *authService) AuthenticateAccount(ctx context.Context, email, password, mfaCode string) (*model.User, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// L1: same bcrypt cost as a known email with a wrong password.
		auth.CheckDummyPassword()
		return nil, ErrInvalidCredentials
	}
	if err := s.checkPasswordWithLockout(ctx, user, password, ""); err != nil {
		return nil, err
	}
	if !user.IsVerified {
		return nil, fmt.Errorf("%w: please verify your email first", ErrUserNotVerified)
	}
	if user.IsGlobalAdmin() {
		return nil, ErrAccountPageAdmin
	}
	if err := s.stepUpMFA(ctx, user, mfaCode); err != nil {
		if errors.Is(err, ErrMFAInvalidCode) {
			s.logSecurityEvent(ctx, model.SecurityEventLoginFailed, &user.ID, nil, false, map[string]interface{}{
				"email":   user.Email,
				"reason":  "mfa_invalid",
				"context": "account_security",
			})
		}
		return nil, err
	}
	if err := s.resetFailedAttempts(ctx, user.ID); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}
	s.logSecurityEvent(ctx, model.SecurityEventLoginSuccess, &user.ID, nil, true, map[string]interface{}{
		"email":   user.Email,
		"context": "account_security",
	})
	return user, nil
}

// AdminLogin authenticates an admin user for the admin portal (no app context)
func (s *authService) AdminLogin(ctx context.Context, req dto.AdminLoginRequest) (*dto.LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		// L1 fix: see Login — pay the same bcrypt cost as a real password
		// check so an unknown email is not distinguishable by timing.
		auth.CheckDummyPassword()
		return nil, ErrInvalidCredentials
	}

	// The same password check, failure counting and lockout as every other
	// sign-in path.
	if err := s.checkPasswordWithLockout(ctx, user, req.Password, "admin_portal"); err != nil {
		return nil, err
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

	// Admin MFA-enrollment policy (RFC-011): under "enforce", an admin without
	// MFA is denied until they enroll; under "observe" the gap is only audited.
	if err := s.enforceAdminMFAPolicy(ctx, user, "admin_portal"); err != nil {
		return nil, err
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
	if err := s.resetFailedAttempts(ctx, user.ID); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}
	// Only the sign-in times are written: user was loaded before the password
	// and MFA checks, and a full-row save would undo a change made meanwhile.
	now := time.Now()
	user.LastLogin = &now
	user.LastLoginAttempt = &now
	user.UpdatedAt = now
	if err := s.userRepo.RecordLogin(ctx, user.ID, now, true); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}

	// Create a virtual "admin-portal" app for token generation
	adminApp := &model.App{
		ID:       0,
		ClientID: AdminPortalClientID,
		Name:     "Admin Portal",
	}

	amr, acr := loginAuthnContext(user.MFAEnabled)
	tokenSet, err := s.tokenService.GenerateTokenSetWithAuth(
		user, adminApp, string(user.Role),
		"openid email profile offline_access",
		make(map[string]string), "", now.Unix(), amr, acr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Log successful admin login
	s.logSecurityEvent(ctx, model.SecurityEventLoginSuccess, &user.ID, nil, true, map[string]interface{}{
		"email":      user.Email,
		"login_type": "admin_portal",
	})
	hooks.RunAfterLogin(ctx, hooks.Login{User: user, Method: "admin_password", MFA: user.MFAEnabled})

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

// RefreshTokens redeems a refresh token presented at POST /api/auth/refresh.
//
// It delegates to the single hardened refresh grant shared with the
// /oauth/token endpoint (rotation, single-use/replay detection, token-family
// revocation on reuse, and DPoP binding) so the platform has exactly one
// refresh code path. The client is identified by the refresh token's own
// audience claim; confidential clients (those with a stored secret) must use
// /oauth/token with client authentication.
//
// The previous implementation here was a second, weaker path that performed no
// rotation or replay detection — it has been removed (Tier-0 hardening).
func (s *authService) RefreshTokens(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error) {
	if s.refreshGranter == nil {
		// Misconfiguration: refuse rather than silently fall back to an
		// unhardened path. Bootstrap must wire SetRefreshGranter.
		logger.FromContext(ctx).Error("auth: refresh granter not configured; refresh rejected")
		return nil, fmt.Errorf("%w: refresh path not configured", ErrInvalidToken)
	}
	return s.refreshGranter.RefreshFromBearer(ctx, refreshToken)
}

// ReverifyForMFAChange re-proves an account before its second factor is turned
// off (P3-9): its password, when password is given and the account has one,
// then a valid TOTP code or an unused recovery code (redeemed on success). A
// wrong password or code counts toward the account lockout, and a locked
// account is refused before anything is checked, as on every sign-in path:
// a stolen access token is not a way to guess the factors without limit.
// The failed-attempt counter is not reset on success (only a sign-in resets
// it). ErrMFANotEnrolled when the account has no second factor; it fails
// closed when no MFA verifier is wired.
func (s *authService) ReverifyForMFAChange(ctx context.Context, userID uint, password *string, code string) error {
	if s.mfa == nil {
		return errors.New("auth: no MFA verifier wired")
	}
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}
	if !user.MFAEnabled {
		return ErrMFANotEnrolled
	}
	if password != nil && user.HashedPassword != "" {
		if err := s.checkPasswordWithLockout(ctx, user, *password, "mfa_disable"); err != nil {
			return err
		}
	} else if locked, _ := s.lockedOut(ctx, user); locked {
		return fmt.Errorf("%w: try again later", ErrAccountLocked)
	}
	return s.stepUpMFA(ctx, user, code)
}

// ReAuthenticate verifies the password (and MFA, if enrolled) of an already
// authenticated admin and issues a token set whose auth_time is now — the
// "step-up" used to satisfy middleware.RequireFreshAuth on destructive routes.
//
// Only a fresh access token is returned (RefreshToken is intentionally blank):
// elevation proves presence, it does not start a new session, so the admin's
// existing refresh token / cookie is left untouched.
func (s *authService) ReAuthenticate(ctx context.Context, userID uint, password, mfaCode string) (*dto.LoginResponse, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: user_id=%d", ErrUserNotFound, userID)
	}

	// A wrong password counts toward the lockout and a locked account is
	// refused, as on every sign-in path.
	if err := s.checkPasswordWithLockout(ctx, user, password, "admin_elevate"); err != nil {
		return nil, err
	}

	// MFA step-up, same as interactive login.
	if err := s.stepUpMFA(ctx, user, mfaCode); err != nil {
		return nil, err
	}
	if err := s.resetFailedAttempts(ctx, user.ID); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
	}

	now := time.Now()
	adminApp := &model.App{ID: 0, ClientID: AdminPortalClientID, Name: "Admin Portal"}
	amr, acr := loginAuthnContext(user.MFAEnabled)
	tokenSet, err := s.tokenService.GenerateTokenSetWithAuth(
		user, adminApp, string(user.Role),
		"openid email profile",
		make(map[string]string), "", now.Unix(), amr, acr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.logSecurityEvent(ctx, model.SecurityEventLoginSuccess, &user.ID, nil, true, map[string]interface{}{
		"email":      user.Email,
		"login_type": "admin_elevate",
	})
	hooks.RunAfterLogin(ctx, hooks.Login{User: user, Method: "admin_elevate", MFA: user.MFAEnabled})

	return &dto.LoginResponse{
		AccessToken:  tokenSet.AccessToken,
		RefreshToken: "", // elevation does not rotate the session
		IDToken:      tokenSet.IDToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokenSet.ExpiresIn,
		UserID:       user.ID,
		Roles:        []string{string(user.Role)},
		AppRoles:     make(map[string]string),
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

	userID, err := strconv.ParseUint(claims.Subject, 10, strconv.IntSize)
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

	// #366: a link issued before the password last changed (by a reset, a
	// change, an admin or an activation) no longer resets it, so an old link
	// left in a mailbox cannot undo a newer password. It is used up as well.
	// iat has one-second precision, so the change time is compared at the
	// same precision: a link requested in the same second as a change, after
	// it, still works (a link issued in that second before the change does
	// too — it went to the same mailbox, less than a second earlier).
	if user.PasswordChangedAt != nil && (claims.IssuedAt == nil || claims.IssuedAt.Before(user.PasswordChangedAt.Truncate(time.Second))) {
		return fmt.Errorf("%w: the password changed after this link was issued", ErrInvalidToken)
	}

	hashedPassword, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// The new password, the cleared forced-change flag and the revocation of
	// every existing token are one write.
	// Written only if the password has not changed since it was read above,
	// so a change that lands meanwhile is not overwritten by this link.
	now := time.Now()
	if err := s.userRepo.SetPassword(ctx, user.ID, repository.PasswordChange{
		HashedPassword: hashedPassword, ClearMustChangePassword: true, ChangedAt: &now,
		OnlyIfUnchangedSince: &repository.PasswordState{ChangedAt: user.PasswordChangedAt},
	}); err != nil {
		if errors.Is(err, repository.ErrPasswordChangedMeanwhile) {
			return fmt.Errorf("%w: the password changed after this link was issued", ErrInvalidToken)
		}
		return fmt.Errorf("failed to update password: %w", err)
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

	// Verify the current password: a wrong one counts toward the lockout and
	// a locked account is refused, as on every sign-in path.
	if err := s.checkPasswordWithLockout(ctx, user, currentPassword, "change_password"); err != nil {
		return err
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

	// The new password and the revocation of every existing token (the user
	// must sign in again) are one write.
	now := time.Now()
	if err := s.userRepo.SetPassword(ctx, user.ID, repository.PasswordChange{
		HashedPassword: hashedPassword, ClearMustChangePassword: true, ChangedAt: &now,
	}); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	if err := s.resetFailedAttempts(ctx, user.ID); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
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

// InvitePending reports whether u is an account that is still waiting for an
// invite to activate it: created by an administrator or an application with a
// throwaway password (Source "manual" or "invite"), never verified and never
// signed in. Any other account belongs to someone already, and an invite must
// not change its password.
func InvitePending(u *model.User) bool {
	return !u.IsVerified && u.LastLogin == nil && u.ConfirmedAt == nil &&
		(u.Source == "manual" || u.Source == "invite") && !u.IsGlobalAdmin()
}

// InviteOwnerApp returns the application whose invite may activate the
// pending account u, and false when no application may. It is the app
// recorded when the invite created the account (u.InviteAppID). For an account
// created before that was recorded (InviteAppID nil), it is the app of the
// account's oldest role in roles, the one that invited it first; an account
// with no role has none.
func InviteOwnerApp(u *model.User, roles []model.UserAppRole) (uint, bool) {
	if u.InviteAppID != nil {
		return *u.InviteAppID, true
	}
	var oldest *model.UserAppRole
	for i := range roles {
		r := &roles[i]
		if r.UserID != u.ID {
			continue
		}
		if oldest == nil || r.ID < oldest.ID {
			oldest = r
		}
	}
	if oldest == nil {
		return 0, false
	}
	return oldest.AppID, true
}

// inviteActivates reports whether an invite for appID may activate the pending
// account u. It reads u's roles only for an account that does not record the
// app that created it; when they cannot be read it returns an error, and the
// caller refuses the invite.
func (s *authService) inviteActivates(ctx context.Context, u *model.User, appID uint) (bool, error) {
	var roles []model.UserAppRole
	if u.InviteAppID == nil {
		var err error
		if roles, err = s.userAppRoleRepo.FindByUser(ctx, u.ID); err != nil {
			logger.FromContext(ctx).Warnf("auth: accept invite: read roles of user %d: %v", u.ID, err)
			return false, fmt.Errorf("failed to read roles: %w", err)
		}
	}
	owner, ok := InviteOwnerApp(u, roles)
	return ok && owner == appID, nil
}

// AcceptInvite accepts an invite: it creates the account, or activates the one
// the invite created. It never sets the password of an account already in use
// (ErrInviteAccountActive), and an invite only activates a pending account
// created for the same app (ErrInviteForOtherApp).
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

	// The account checks come before the token is claimed, so an invite that
	// is refused (or fails on a read error) stays usable.
	user, err := s.userRepo.FindByEmail(ctx, claims.Email)
	existing := err == nil
	if existing {
		// An invite token is handed to whoever sent the invite (the API returns
		// it to the app admin or service account), so it must never change the
		// password of an account that is already in use: only the account the invite
		// created, still waiting to be activated, gets its password set here.
		if !InvitePending(user) {
			return nil, ErrInviteAccountActive
		}
		// A pending account is activated only by an invite of the app that
		// created it: an app that adds an existing pending account gets the
		// role, not the right to set its password.
		activates, err := s.inviteActivates(ctx, user, claims.AppID)
		if err != nil {
			return nil, err
		}
		if !activates {
			appID := claims.AppID
			s.logSecurityEvent(ctx, model.SecurityEventInviteAccepted, &user.ID, &appID, false, map[string]interface{}{
				"email":  user.Email,
				"reason": "invite_other_app",
			})
			return nil, ErrInviteForOtherApp
		}
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

	if !existing {
		// Create new user
		inviteAppID := claims.AppID
		user = &model.User{
			Email:          claims.Email,
			Name:           userName,
			HashedPassword: hashedPassword,
			Role:           model.UserRoleUser,
			IsVerified:     true,
			TokenVersion:   1,
			Source:         "invite",
			InviteAppID:    &inviteAppID,
			ConfirmedAt:    &now,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		if err := s.userRepo.Create(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
		hooks.RunUserProvisioned(ctx, hooks.UserProvisioned{User: user, Source: "invite"})
	} else {
		if userName != "" && userName != claims.Email {
			user.Name = userName
			user.UpdatedAt = now
			if err := s.userRepo.Update(ctx, user); err != nil {
				return nil, fmt.Errorf("failed to update user: %w", err)
			}
		}
		// The password and the verification are one write (Update never
		// writes a password); it also moves the token version, so read the
		// user back for the tokens issued below.
		// Recording the change retires the reset links issued before it (#366).
		if err := s.userRepo.SetPassword(ctx, user.ID, repository.PasswordChange{
			HashedPassword: hashedPassword, ConfirmedAt: &now, ChangedAt: &now,
		}); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		if user, err = s.userRepo.FindByID(ctx, user.ID); err != nil {
			return nil, fmt.Errorf("failed to reload user: %w", err)
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
	user.UpdatedAt = now
	if err := s.userRepo.RecordLogin(ctx, user.ID, now, false); err != nil {
		logger.FromContext(ctx).Warnf("auth: non-fatal error persisting user state, continuing: %v", err)
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
