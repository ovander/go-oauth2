// Package service — unit tests for MFAService (TOTP enrollment / verification).
//
// These tests use an in-memory UserRepository stub (no database) together with
// the real totp and auth (secret-encryption) packages, so they exercise the
// full enroll → confirm → verify → disable lifecycle end-to-end.
package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/totp"
)

// ---------------------------------------------------------------------------
// In-memory UserRepository stub (supports FindByID + Update)
// ---------------------------------------------------------------------------

// mfaMemUserRepo is a minimal in-memory UserRepository that persists Update so
// the MFA enroll/confirm/verify/disable round-trip can be observed.
type mfaMemUserRepo struct {
	users       map[uint]*model.User
	updateCalls int
}

func newMFAMemUserRepo(us ...*model.User) *mfaMemUserRepo {
	m := &mfaMemUserRepo{users: make(map[uint]*model.User)}
	for _, u := range us {
		m.users[u.ID] = u
	}
	return m
}

func (r *mfaMemUserRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, errors.New("record not found")
	}
	// Return a copy so the service mutates its own struct, mirroring GORM
	// (which hydrates a fresh row each FindByID); Update persists it back.
	cp := *u
	return &cp, nil
}

func (r *mfaMemUserRepo) Update(_ context.Context, user *model.User) error {
	r.updateCalls++
	cp := *user
	r.users[user.ID] = &cp
	return nil
}

// --- stubs for the rest of the interface (not exercised by MFA) ---

func (r *mfaMemUserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error) {
	panic("not implemented")
}
func (r *mfaMemUserRepo) FindByEmail(_ context.Context, _ string) (*model.User, error) {
	panic("not implemented")
}
func (r *mfaMemUserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) {
	panic("not implemented")
}
func (r *mfaMemUserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error) {
	panic("not implemented")
}
func (r *mfaMemUserRepo) Create(_ context.Context, _ *model.User) error { panic("not implemented") }
func (r *mfaMemUserRepo) Delete(_ context.Context, _ uint) error        { panic("not implemented") }
func (r *mfaMemUserRepo) IncrementTokenVersion(_ context.Context, _ uint) error {
	panic("not implemented")
}
func (r *mfaMemUserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error {
	panic("not implemented")
}
func (r *mfaMemUserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error {
	panic("not implemented")
}
func (r *mfaMemUserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error {
	panic("not implemented")
}

// Compile-time interface check.
var _ repository.UserRepository = (*mfaMemUserRepo)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var testEncKey = []byte("test-secret-key-base-for-mfa-aes")

func newTestMFAService(repo repository.UserRepository) MFAService {
	return NewMFAService(repo, testEncKey, "Socrate")
}

// ---------------------------------------------------------------------------
// BeginEnrollment
// ---------------------------------------------------------------------------

func TestMFA_BeginEnrollment_StoresEncryptedSecret(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	secret, uri, err := svc.BeginEnrollment(context.Background(), 1)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if secret == "" {
		t.Fatal("expected a non-empty secret")
	}
	if uri == "" {
		t.Fatal("expected a non-empty provisioning URI")
	}

	stored := repo.users[1]
	if stored.MFAEnabled {
		t.Error("MFA must remain disabled until enrollment is confirmed")
	}
	if stored.MFASecret == "" {
		t.Fatal("expected the encrypted secret to be persisted")
	}
	if stored.MFASecret == secret {
		t.Error("stored secret must be ciphertext, not the plaintext secret")
	}
}

func TestMFA_BeginEnrollment_ProvisioningURIContainsAccount(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	_, uri, err := svc.BeginEnrollment(context.Background(), 1)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if !contains(uri, "otpauth://totp/") {
		t.Errorf("expected an otpauth URI, got %q", uri)
	}
	if !contains(uri, "issuer=Socrate") {
		t.Errorf("expected the issuer in the URI, got %q", uri)
	}
}

func TestMFA_BeginEnrollment_AlreadyEnabled(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com", MFAEnabled: true})
	svc := newTestMFAService(repo)

	_, _, err := svc.BeginEnrollment(context.Background(), 1)
	if !errors.Is(err, ErrMFAAlreadyEnabled) {
		t.Fatalf("expected ErrMFAAlreadyEnabled, got %v", err)
	}
}

func TestMFA_BeginEnrollment_UnknownUser(t *testing.T) {
	repo := newMFAMemUserRepo()
	svc := newTestMFAService(repo)

	if _, _, err := svc.BeginEnrollment(context.Background(), 99); err == nil {
		t.Fatal("expected an error for an unknown user")
	}
}

// ---------------------------------------------------------------------------
// ConfirmEnrollment
// ---------------------------------------------------------------------------

func TestMFA_ConfirmEnrollment_ValidCodeEnables(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	secret, _, err := svc.BeginEnrollment(context.Background(), 1)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := svc.ConfirmEnrollment(context.Background(), 1, code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	if !repo.users[1].MFAEnabled {
		t.Error("expected MFA to be enabled after a valid confirmation")
	}
}

func TestMFA_ConfirmEnrollment_WrongCode(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	if _, _, err := svc.BeginEnrollment(context.Background(), 1); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if err := svc.ConfirmEnrollment(context.Background(), 1, "000000"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode, got %v", err)
	}
	if repo.users[1].MFAEnabled {
		t.Error("MFA must stay disabled when confirmation fails")
	}
}

func TestMFA_ConfirmEnrollment_NotEnrolled(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	if err := svc.ConfirmEnrollment(context.Background(), 1, "123456"); !errors.Is(err, ErrMFANotEnrolled) {
		t.Fatalf("expected ErrMFANotEnrolled, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

func TestMFA_Verify_EnabledUser(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	secret, _, err := svc.BeginEnrollment(context.Background(), 1)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := svc.ConfirmEnrollment(context.Background(), 1, code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	if err := svc.Verify(context.Background(), 1, code); err != nil {
		t.Fatalf("Verify with valid code: %v", err)
	}
	if err := svc.Verify(context.Background(), 1, "000000"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode for a wrong code, got %v", err)
	}
}

func TestMFA_Verify_NotEnabled(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	if err := svc.Verify(context.Background(), 1, "123456"); !errors.Is(err, ErrMFANotEnrolled) {
		t.Fatalf("expected ErrMFANotEnrolled, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Disable / IsEnabled
// ---------------------------------------------------------------------------

func TestMFA_Disable_ClearsSecretAndFlag(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	secret, _, err := svc.BeginEnrollment(context.Background(), 1)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := svc.ConfirmEnrollment(context.Background(), 1, code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	if err := svc.Disable(context.Background(), 1); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if repo.users[1].MFAEnabled {
		t.Error("expected MFA disabled after Disable")
	}
	if repo.users[1].MFASecret != "" {
		t.Error("expected the stored secret cleared after Disable")
	}
}

func TestMFA_IsEnabled(t *testing.T) {
	repo := newMFAMemUserRepo(&model.User{ID: 1, Email: "alice@example.com"})
	svc := newTestMFAService(repo)

	enabled, err := svc.IsEnabled(context.Background(), 1)
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if enabled {
		t.Error("expected MFA disabled for a fresh user")
	}

	secret, _, err := svc.BeginEnrollment(context.Background(), 1)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := svc.ConfirmEnrollment(context.Background(), 1, code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	enabled, err = svc.IsEnabled(context.Background(), 1)
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if !enabled {
		t.Error("expected MFA enabled after confirmation")
	}
}

// contains is a tiny helper to keep assertions readable.
func contains(s, sub string) bool { return strings.Contains(s, sub) }
