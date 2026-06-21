package service

import (
	"context"
	"errors"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/totp"
)

// MFA service errors.
var (
	ErrMFANotEnrolled    = errors.New("mfa: not enrolled")
	ErrMFAInvalidCode    = errors.New("mfa: invalid code")
	ErrMFAAlreadyEnabled = errors.New("mfa: already enabled")
)

// MFAService manages a user's TOTP multi-factor authentication lifecycle. The
// TOTP secret is stored encrypted at rest (auth.EncryptSecret, keyed by
// SECRET_KEY_BASE); a database compromise alone does not reveal it.
type MFAService interface {
	// BeginEnrollment generates a new TOTP secret, stores it encrypted (leaving
	// MFA disabled until confirmed), and returns the plaintext secret and an
	// otpauth:// provisioning URI for the user's authenticator app.
	BeginEnrollment(ctx context.Context, userID uint) (secret, provisioningURI string, err error)
	// ConfirmEnrollment validates a code against the pending secret and, on
	// success, enables MFA for the user.
	ConfirmEnrollment(ctx context.Context, userID uint, code string) error
	// Verify checks a code for an MFA-enabled user (login step-up).
	Verify(ctx context.Context, userID uint, code string) error
	// Disable clears the user's MFA secret and flag.
	Disable(ctx context.Context, userID uint) error
	// IsEnabled reports whether MFA is enabled for the user.
	IsEnabled(ctx context.Context, userID uint) (bool, error)
}

type mfaService struct {
	userRepo repository.UserRepository
	encKey   []byte
	issuer   string
}

// NewMFAService builds an MFAService. encKey (SECRET_KEY_BASE) encrypts the
// stored TOTP secret; issuer labels the provisioning URI.
func NewMFAService(userRepo repository.UserRepository, encKey []byte, issuer string) MFAService {
	return &mfaService{userRepo: userRepo, encKey: encKey, issuer: issuer}
}

func (s *mfaService) BeginEnrollment(ctx context.Context, userID uint) (string, string, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if user.MFAEnabled {
		return "", "", ErrMFAAlreadyEnabled
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		return "", "", err
	}
	ciphertext, err := auth.EncryptSecret(s.encKey, secret)
	if err != nil {
		return "", "", err
	}

	user.MFASecret = ciphertext
	user.MFAEnabled = false
	if err := s.userRepo.Update(ctx, user); err != nil {
		return "", "", err
	}
	return secret, totp.ProvisioningURI(secret, user.Email, s.issuer), nil
}

func (s *mfaService) ConfirmEnrollment(ctx context.Context, userID uint, code string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.MFASecret == "" {
		return ErrMFANotEnrolled
	}
	secret, err := auth.DecryptSecret(s.encKey, user.MFASecret)
	if err != nil {
		return err
	}
	if !totp.ValidateCode(secret, code, time.Now()) {
		return ErrMFAInvalidCode
	}
	user.MFAEnabled = true
	return s.userRepo.Update(ctx, user)
}

func (s *mfaService) Verify(ctx context.Context, userID uint, code string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.MFAEnabled || user.MFASecret == "" {
		return ErrMFANotEnrolled
	}
	secret, err := auth.DecryptSecret(s.encKey, user.MFASecret)
	if err != nil {
		return err
	}
	if !totp.ValidateCode(secret, code, time.Now()) {
		return ErrMFAInvalidCode
	}
	return nil
}

func (s *mfaService) Disable(ctx context.Context, userID uint) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	user.MFASecret = ""
	user.MFAEnabled = false
	return s.userRepo.Update(ctx, user)
}

func (s *mfaService) IsEnabled(ctx context.Context, userID uint) (bool, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return false, err
	}
	return user.MFAEnabled, nil
}
