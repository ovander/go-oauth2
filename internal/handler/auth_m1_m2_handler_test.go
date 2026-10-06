// Package handler — tests for the Socrate suite audit remediation:
//
// M1: auth_handler.go / admin_auth_handler.go must not forward raw
// service/GORM error strings (err.Error()) to unauthenticated callers. Known
// sentinel errors map to static, safe messages; anything else collapses to a
// generic message, with the real error logged server-side.
//
// M2: the Login handlers must use errors.Is, not == / a bare switch, when
// comparing against service sentinel errors — service.Login/AdminLogin wrap
// several of them (ErrAccountLocked, ErrUserNotVerified, ErrAppNotFound,
// ErrRoleNotFound), which an equality comparison misses, falling through to
// the default branch and (pre-fix) leaking err.Error() with the wrong status
// code.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// m1m2AuthService is a configurable service.AuthService stub: each method
// returns its injected closure's result, or panics if the closure is nil, so
// a test cannot accidentally pass by exercising an untested code path.
type m1m2AuthService struct {
	signup      func(ctx context.Context, req dto.SignupRequest) (*model.User, string, error)
	verifyEmail func(ctx context.Context, token string) error
	login       func(ctx context.Context, req dto.LoginRequest) (*dto.LoginResponse, error)
	adminLogin  func(ctx context.Context, req dto.AdminLoginRequest) (*dto.LoginResponse, error)
}

func (s *m1m2AuthService) Signup(ctx context.Context, req dto.SignupRequest) (*model.User, string, error) {
	if s.signup != nil {
		return s.signup(ctx, req)
	}
	panic("Signup called unexpectedly")
}
func (s *m1m2AuthService) VerifyEmail(ctx context.Context, token string) error {
	if s.verifyEmail != nil {
		return s.verifyEmail(ctx, token)
	}
	panic("VerifyEmail called unexpectedly")
}
func (s *m1m2AuthService) Login(ctx context.Context, req dto.LoginRequest) (*dto.LoginResponse, error) {
	if s.login != nil {
		return s.login(ctx, req)
	}
	panic("Login called unexpectedly")
}
func (s *m1m2AuthService) AdminLogin(ctx context.Context, req dto.AdminLoginRequest) (*dto.LoginResponse, error) {
	if s.adminLogin != nil {
		return s.adminLogin(ctx, req)
	}
	panic("AdminLogin called unexpectedly")
}
func (s *m1m2AuthService) RefreshTokens(_ context.Context, _ string) (*dto.RefreshResponse, error) {
	panic("RefreshTokens called unexpectedly")
}
func (s *m1m2AuthService) Logout(_ context.Context, _ uint) error {
	panic("Logout called unexpectedly")
}
func (s *m1m2AuthService) RequestPasswordReset(_ context.Context, _ string, _ *auth.AppContext) (string, error) {
	panic("RequestPasswordReset called unexpectedly")
}
func (s *m1m2AuthService) ResetPassword(_ context.Context, _, _ string) error {
	panic("ResetPassword called unexpectedly")
}
func (s *m1m2AuthService) ChangePassword(_ context.Context, _ uint, _, _ string) error {
	panic("ChangePassword called unexpectedly")
}
func (s *m1m2AuthService) ValidateInviteToken(_ context.Context, _ string) (*dto.InviteValidationResponse, error) {
	panic("ValidateInviteToken called unexpectedly")
}
func (s *m1m2AuthService) AcceptInvite(_ context.Context, _, _, _ string) (*dto.LoginResponse, error) {
	panic("AcceptInvite called unexpectedly")
}
func (s *m1m2AuthService) WithMFA(_ service.MFAService) service.AuthService { return s }
func (s *m1m2AuthService) AuthenticateAccount(context.Context, string, string, string) (*model.User, error) {
	return nil, errors.New("not used")
}

var _ service.AuthService = (*m1m2AuthService)(nil)

// m1m2UserService is a no-op UserService stub (required by NewAuthHandler but
// unused by the Login/Signup/VerifyEmail paths under test).
type m1m2UserService struct{}

func (s *m1m2UserService) List(_ context.Context, _, _ int) ([]model.User, int64, error) {
	return nil, 0, nil
}
func (s *m1m2UserService) GetByID(_ context.Context, _ uint) (*model.User, error) { return nil, nil }
func (s *m1m2UserService) GetByEmail(_ context.Context, _ string) (*model.User, error) {
	return nil, nil
}
func (s *m1m2UserService) Create(_ context.Context, _ dto.CreateUserRequest) (*model.User, error) {
	return nil, nil
}
func (s *m1m2UserService) Update(_ context.Context, _ uint, _ dto.UpdateUserRequest) (*model.User, error) {
	return nil, nil
}
func (s *m1m2UserService) UpdateProfile(_ context.Context, _ uint, _ dto.UpdateProfileRequest) (*model.User, error) {
	return nil, nil
}
func (s *m1m2UserService) Delete(_ context.Context, _ uint) error                   { return nil }
func (s *m1m2UserService) VerifyEmail(_ context.Context, _ uint) error              { return nil }
func (s *m1m2UserService) UpdatePassword(_ context.Context, _ uint, _ string) error { return nil }
func (s *m1m2UserService) IncrementTokenVersion(_ context.Context, _ uint) error    { return nil }
func (s *m1m2UserService) RevokeTokens(_ context.Context, _ uint) error             { return nil }
func (s *m1m2UserService) Unlock(_ context.Context, _ uint) error                   { return nil }
func (s *m1m2UserService) ListSuperadmins(_ context.Context) ([]model.User, error)  { return nil, nil }
func (s *m1m2UserService) CountSuperadmins(_ context.Context) (int64, error)        { return 0, nil }
func (s *m1m2UserService) CreateSuperadmin(_ context.Context, _ dto.CreateSuperadminRequest) (*model.User, error) {
	return nil, nil
}
func (s *m1m2UserService) UpdateSuperadmin(_ context.Context, _ uint, _ dto.UpdateSuperadminRequest) (*model.User, error) {
	return nil, nil
}
func (s *m1m2UserService) DeleteSuperadmin(_ context.Context, _ uint, _ uint) error { return nil }
func (s *m1m2UserService) Block(_ context.Context, _ uint) error                    { return nil }

var _ service.UserService = (*m1m2UserService)(nil)

// decodeErrorBody decodes a dto.ErrorResponse body for assertions.
func decodeErrorBody(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp dto.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode ErrorResponse: %v (raw body: %s)", err, rr.Body.String())
	}
	return resp.Error
}

// ---------------------------------------------------------------------------
// M2: Login must use errors.Is against wrapped service sentinels
// ---------------------------------------------------------------------------

func TestM2_Login_WrappedAccountLocked_MapsToLockedResponse(t *testing.T) {
	authSvc := &m1m2AuthService{
		login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
			// service.Login wraps ErrAccountLocked: fmt.Errorf("%w: try again later", ...).
			return nil, fmt.Errorf("%w: try again later", service.ErrAccountLocked)
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	body := `{"email":"a@example.com","password":"x","app_client_id":"app1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (M2: wrapped ErrAccountLocked must hit its intended branch)", rr.Code, http.StatusForbidden)
	}
	if msg := decodeErrorBody(t, rr); msg != "account is locked" {
		t.Errorf("error = %q, want %q", msg, "account is locked")
	}
}

func TestM2_Login_WrappedUserNotVerified_MapsToForbiddenResponse(t *testing.T) {
	authSvc := &m1m2AuthService{
		login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
			return nil, fmt.Errorf("%w: please verify your email first", service.ErrUserNotVerified)
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	body := `{"email":"a@example.com","password":"x","app_client_id":"app1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if msg := decodeErrorBody(t, rr); msg != "email not verified" {
		t.Errorf("error = %q, want %q", msg, "email not verified")
	}
}

func TestM2_Login_WrappedAppNotFound_DoesNotLeakClientID(t *testing.T) {
	authSvc := &m1m2AuthService{
		login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
			// service.Login wraps ErrAppNotFound with the raw client_id — this is
			// exactly the M1 leak the audit flagged.
			return nil, fmt.Errorf("%w: client_id=some-internal-app-slug", service.ErrAppNotFound)
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	body := `{"email":"a@example.com","password":"x","app_client_id":"some-internal-app-slug"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	msg := decodeErrorBody(t, rr)
	if strings.Contains(msg, "client_id=") || strings.Contains(msg, "app not found") {
		t.Errorf("M1: response leaked the wrapped internal error text, got %q", msg)
	}
	if msg != "unknown client_id" {
		t.Errorf("error = %q, want static message %q", msg, "unknown client_id")
	}
}

func TestM2_Login_WrappedRoleNotFound_DoesNotLeak(t *testing.T) {
	authSvc := &m1m2AuthService{
		login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
			return nil, fmt.Errorf("%w: user has no access to app", service.ErrRoleNotFound)
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	body := `{"email":"a@example.com","password":"x","app_client_id":"app1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	msg := decodeErrorBody(t, rr)
	if strings.Contains(msg, "no access to app") {
		t.Errorf("M1: response leaked the wrapped internal error text, got %q", msg)
	}
}

// ---------------------------------------------------------------------------
// M1: unclassified errors collapse to a static message; the real error is
// never forwarded to the client.
// ---------------------------------------------------------------------------

func TestM1_Login_UnclassifiedError_NoLeak(t *testing.T) {
	sensitive := errors.New("pq: connection refused at 10.0.4.12:5432")
	authSvc := &m1m2AuthService{
		login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
			return nil, sensitive
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	body := `{"email":"a@example.com","password":"x","app_client_id":"app1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	msg := decodeErrorBody(t, rr)
	if strings.Contains(msg, "pq:") || strings.Contains(msg, "10.0.4.12") {
		t.Errorf("M1: response leaked the raw internal error text, got %q", msg)
	}
	if msg != "login failed" {
		t.Errorf("error = %q, want static fallback message %q", msg, "login failed")
	}
}

func TestM1_Signup_AppNotFound_NoLeak(t *testing.T) {
	authSvc := &m1m2AuthService{
		signup: func(_ context.Context, _ dto.SignupRequest) (*model.User, string, error) {
			return nil, "", fmt.Errorf("%w: client_id=leaked-internal-slug", service.ErrAppNotFound)
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	body := `{"email":"a@example.com","name":"A","password":"x","client_id":"leaked-internal-slug"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Signup(rr, req)

	msg := decodeErrorBody(t, rr)
	if strings.Contains(msg, "client_id=") {
		t.Errorf("M1: signup response leaked the wrapped internal error text, got %q", msg)
	}
	if msg != "unknown client_id" {
		t.Errorf("error = %q, want static message %q", msg, "unknown client_id")
	}
}

func TestM1_Signup_EmailAlreadyExists_NoLeak(t *testing.T) {
	authSvc := &m1m2AuthService{
		signup: func(_ context.Context, _ dto.SignupRequest) (*model.User, string, error) {
			return nil, "", fmt.Errorf("%w: someone@example.com", service.ErrEmailAlreadyExists)
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	body := `{"email":"someone@example.com","name":"A","password":"x","client_id":"app1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Signup(rr, req)

	if msg := decodeErrorBody(t, rr); msg != "email already exists" {
		t.Errorf("error = %q, want static message %q", msg, "email already exists")
	}
}

func TestM1_Signup_PasswordValidationError_IsPassedThrough(t *testing.T) {
	// Password-validation feedback is a fixed, safe description (no wrapped
	// internal detail) and is meant to be shown to the caller — it must NOT
	// be collapsed to the generic fallback message.
	authSvc := &m1m2AuthService{
		signup: func(_ context.Context, _ dto.SignupRequest) (*model.User, string, error) {
			return nil, "", fmt.Errorf("password validation failed: %w", auth.ErrPasswordTooShort)
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	body := `{"email":"a@example.com","name":"A","password":"short","client_id":"app1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Signup(rr, req)

	msg := decodeErrorBody(t, rr)
	if !strings.Contains(msg, "at least 12 characters") {
		t.Errorf("expected password-validation feedback to pass through, got %q", msg)
	}
}

func TestM1_VerifyEmail_UnclassifiedError_NoLeak(t *testing.T) {
	authSvc := &m1m2AuthService{
		verifyEmail: func(_ context.Context, _ string) error {
			return errors.New("gorm: record not found for internal_id=999")
		},
	}
	h := NewAuthHandler(authSvc, &m1m2UserService{}, nil, "production", "https://auth.example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/auth/verify-email?token=abc", nil)
	rr := httptest.NewRecorder()
	h.VerifyEmail(rr, req)

	msg := decodeErrorBody(t, rr)
	if strings.Contains(msg, "gorm:") || strings.Contains(msg, "internal_id") {
		t.Errorf("M1: verify-email response leaked the raw internal error text, got %q", msg)
	}
}

// ---------------------------------------------------------------------------
// M2/M1 mirrored fix: admin_auth_handler.go's Login has the identical bug
// pattern (switch err {} instead of errors.Is, default: err.Error()).
// ---------------------------------------------------------------------------

func TestM2_AdminLogin_WrappedAccountLocked_MapsToLockedResponse(t *testing.T) {
	authSvc := &m1m2AuthService{
		adminLogin: func(_ context.Context, _ dto.AdminLoginRequest) (*dto.LoginResponse, error) {
			return nil, fmt.Errorf("%w: try again later", service.ErrAccountLocked)
		},
	}
	h := NewAdminAuthHandler(authSvc, &m1m2UserService{})

	body := `{"email":"admin@example.com","password":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (M2: wrapped ErrAccountLocked must hit its intended branch)", rr.Code, http.StatusForbidden)
	}
	if msg := decodeErrorBody(t, rr); msg != "account is locked" {
		t.Errorf("error = %q, want %q", msg, "account is locked")
	}
}

func TestM1_AdminLogin_UnclassifiedError_NoLeak(t *testing.T) {
	authSvc := &m1m2AuthService{
		adminLogin: func(_ context.Context, _ dto.AdminLoginRequest) (*dto.LoginResponse, error) {
			return nil, fmt.Errorf("failed to generate tokens: %w", errors.New("rsa: key too small"))
		},
	}
	h := NewAdminAuthHandler(authSvc, &m1m2UserService{})

	body := `{"email":"admin@example.com","password":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	msg := decodeErrorBody(t, rr)
	if strings.Contains(msg, "rsa:") || strings.Contains(msg, "failed to generate tokens") {
		t.Errorf("M1: admin login response leaked the raw internal error text, got %q", msg)
	}
	if msg != "login failed" {
		t.Errorf("error = %q, want static fallback message %q", msg, "login failed")
	}
}
