package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
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
	// GenerateRecoveryCodes issues a fresh set of one-time backup codes for an
	// MFA-enabled user, replacing any existing set, and returns the plaintext
	// codes once (they are stored only as keyed hashes).
	GenerateRecoveryCodes(ctx context.Context, userID uint) ([]string, error)
	// RedeemRecoveryCode consumes a single recovery code. It reports whether the
	// code was valid and unused (and, if so, marks it used).
	RedeemRecoveryCode(ctx context.Context, userID uint, code string) (bool, error)
}

type mfaService struct {
	userRepo     repository.UserRepository
	recoveryRepo repository.MFARecoveryCodeRepository
	encKey       []byte
	issuer       string
}

// NewMFAService builds an MFAService. encKey (SECRET_KEY_BASE) encrypts the
// stored TOTP secret and keys recovery-code hashes; issuer labels the
// provisioning URI. recoveryRepo may be nil if recovery codes are not used.
func NewMFAService(userRepo repository.UserRepository, recoveryRepo repository.MFARecoveryCodeRepository, encKey []byte, issuer string) MFAService {
	return &mfaService{userRepo: userRepo, recoveryRepo: recoveryRepo, encKey: encKey, issuer: issuer}
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
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}
	// Best-effort: clear any recovery codes so they cannot be redeemed after MFA
	// is turned off.
	if s.recoveryRepo != nil {
		if err := s.recoveryRepo.DeleteByUser(ctx, userID); err != nil {
			return err
		}
	}
	return nil
}

func (s *mfaService) IsEnabled(ctx context.Context, userID uint) (bool, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return false, err
	}
	return user.MFAEnabled, nil
}

// recoveryCodeCount is the number of backup codes issued per regeneration.
const recoveryCodeCount = 10

// GenerateRecoveryCodes issues a fresh set of one-time backup codes for an
// MFA-enabled user, replacing any prior set. The plaintext codes are returned
// once; only their keyed hashes are persisted.
func (s *mfaService) GenerateRecoveryCodes(ctx context.Context, userID uint) ([]string, error) {
	if s.recoveryRepo == nil {
		return nil, errors.New("mfa: recovery codes not configured")
	}
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !user.MFAEnabled {
		return nil, ErrMFANotEnrolled
	}

	plaintext := make([]string, 0, recoveryCodeCount)
	rows := make([]model.MFARecoveryCode, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, code)
		rows = append(rows, model.MFARecoveryCode{
			UserID:   userID,
			CodeHash: s.hashRecoveryCode(code),
		})
	}

	if err := s.recoveryRepo.DeleteByUser(ctx, userID); err != nil {
		return nil, err
	}
	if err := s.recoveryRepo.CreateBatch(ctx, rows); err != nil {
		return nil, err
	}
	return plaintext, nil
}

// RedeemRecoveryCode consumes a single recovery code, returning true when the
// code was valid and unused.
func (s *mfaService) RedeemRecoveryCode(ctx context.Context, userID uint, code string) (bool, error) {
	if s.recoveryRepo == nil {
		return false, nil
	}
	want := s.hashRecoveryCode(code)
	if normalizeRecoveryCode(code) == "" {
		return false, nil
	}
	codes, err := s.recoveryRepo.ListUnusedByUser(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, c := range codes {
		if subtle.ConstantTimeCompare([]byte(c.CodeHash), []byte(want)) == 1 {
			return s.recoveryRepo.MarkUsed(ctx, c.ID)
		}
	}
	return false, nil
}

// hashRecoveryCode returns the hex-encoded HMAC-SHA256 of the normalized code,
// keyed by encKey — a DB dump alone cannot reveal or verify codes.
func (s *mfaService) hashRecoveryCode(code string) string {
	mac := hmac.New(sha256.New, s.encKey)
	mac.Write([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(mac.Sum(nil))
}

// recoveryAlphabet is Crockford-base32-like, excluding ambiguous characters
// (0/o/1/i/l) so codes are easy to read and transcribe.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// generateRecoveryCode returns a new random code formatted as "xxxxx-xxxxx".
func generateRecoveryCode() (string, error) {
	const n = 10
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mfa: generate recovery code: %w", err)
	}
	out := make([]byte, 0, n+1)
	for i := 0; i < n; i++ {
		if i == n/2 {
			out = append(out, '-')
		}
		out = append(out, recoveryAlphabet[int(buf[i])%len(recoveryAlphabet)])
	}
	return string(out), nil
}

// normalizeRecoveryCode lower-cases the code and strips any non-alphanumeric
// characters (dashes, spaces) so display formatting does not affect matching.
func normalizeRecoveryCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(code) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
