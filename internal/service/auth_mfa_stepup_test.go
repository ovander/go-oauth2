package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// stubMFAVerifier is a minimal MFAService for exercising login step-up. Only
// Verify is used by stepUpMFA; the rest panic if unexpectedly called.
type stubMFAVerifier struct {
	verifyErr error
	verifyHit bool
	redeemOK  bool
	redeemErr error
	redeemHit bool
}

func (s *stubMFAVerifier) BeginEnrollment(context.Context, uint) (string, string, error) {
	panic("not used")
}
func (s *stubMFAVerifier) ConfirmEnrollment(context.Context, uint, string) error { panic("not used") }
func (s *stubMFAVerifier) Verify(_ context.Context, _ uint, _ string) error {
	s.verifyHit = true
	return s.verifyErr
}
func (s *stubMFAVerifier) Disable(context.Context, uint) error           { panic("not used") }
func (s *stubMFAVerifier) IsEnabled(context.Context, uint) (bool, error) { panic("not used") }
func (s *stubMFAVerifier) GenerateRecoveryCodes(context.Context, uint) ([]string, error) {
	panic("not used")
}
func (s *stubMFAVerifier) RedeemRecoveryCode(context.Context, uint, string) (bool, error) {
	s.redeemHit = true
	return s.redeemOK, s.redeemErr
}

func TestStepUpMFA_Disabled_NoVerifier(t *testing.T) {
	s := &authService{} // mfa == nil
	user := &model.User{ID: 1, MFAEnabled: true}
	if err := s.stepUpMFA(context.Background(), user, ""); err != nil {
		t.Fatalf("expected nil when no verifier is wired, got %v", err)
	}
}

func TestStepUpMFA_UserNotEnrolled(t *testing.T) {
	stub := &stubMFAVerifier{}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: false}
	if err := s.stepUpMFA(context.Background(), user, "123456"); err != nil {
		t.Fatalf("expected nil for a user without MFA, got %v", err)
	}
	if stub.verifyHit {
		t.Error("Verify must not be called for a non-MFA user")
	}
}

func TestStepUpMFA_EnabledMissingCode(t *testing.T) {
	stub := &stubMFAVerifier{}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: true}
	for _, code := range []string{"", "   "} {
		if err := s.stepUpMFA(context.Background(), user, code); !errors.Is(err, ErrMFARequired) {
			t.Fatalf("code %q: expected ErrMFARequired, got %v", code, err)
		}
	}
	if stub.verifyHit {
		t.Error("Verify must not be called when no code is supplied")
	}
}

func TestStepUpMFA_EnabledValidCode(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: nil}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: true}
	if err := s.stepUpMFA(context.Background(), user, "123456"); err != nil {
		t.Fatalf("expected nil for a valid code, got %v", err)
	}
	if !stub.verifyHit {
		t.Error("Verify should have been called")
	}
}

func TestStepUpMFA_EnabledInvalidCode(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: ErrMFAInvalidCode}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: true}
	if err := s.stepUpMFA(context.Background(), user, "000000"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode, got %v", err)
	}
}

// Any verifier error is normalized to ErrMFAInvalidCode so the caller never
// leaks internal decrypt/lookup details to the login response.
func TestStepUpMFA_NormalizesVerifierError(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: errors.New("decrypt boom")}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: true}
	if err := s.stepUpMFA(context.Background(), user, "000000"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode, got %v", err)
	}
}

// When the TOTP code is wrong but the value is a valid recovery code, step-up
// succeeds (and the code is consumed by RedeemRecoveryCode).
func TestStepUpMFA_RecoveryCodeFallback(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: ErrMFAInvalidCode, redeemOK: true}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: true}
	if err := s.stepUpMFA(context.Background(), user, "abcde-fghij"); err != nil {
		t.Fatalf("expected nil for a valid recovery code, got %v", err)
	}
	if !stub.redeemHit {
		t.Error("RedeemRecoveryCode should have been attempted after TOTP failed")
	}
}

// A valid TOTP code must not trigger a recovery-code redemption (no backup code
// is wasted on a normal login).
func TestStepUpMFA_ValidTOTPDoesNotRedeem(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: nil, redeemOK: true}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: true}
	if err := s.stepUpMFA(context.Background(), user, "123456"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if stub.redeemHit {
		t.Error("RedeemRecoveryCode must not be called when TOTP succeeds")
	}
}

// Neither a valid TOTP code nor a valid recovery code -> ErrMFAInvalidCode.
func TestStepUpMFA_NeitherTOTPNorRecovery(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: ErrMFAInvalidCode, redeemOK: false}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: true}
	if err := s.stepUpMFA(context.Background(), user, "nope"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode, got %v", err)
	}
	if !stub.redeemHit {
		t.Error("RedeemRecoveryCode should have been attempted")
	}
}

// A recovery-repo error during redemption is normalized to ErrMFAInvalidCode.
func TestStepUpMFA_RecoveryRedeemError(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: ErrMFAInvalidCode, redeemErr: errors.New("db down")}
	s := &authService{mfa: stub}
	user := &model.User{ID: 1, MFAEnabled: true}
	if err := s.stepUpMFA(context.Background(), user, "nope"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode, got %v", err)
	}
}
