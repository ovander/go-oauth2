// Package handler — tests for MED-03 (email verify token not exposed outside
// "development" / "dev" environments).
//
// MED-03 fix: the Signup handler no longer includes the raw verification token
// in the JSON response for ENV=test or ENV=production.  Only ENV=development
// and ENV=dev expose it (for local developer convenience).  This prevents a
// staging server accidentally running with ENV=test from leaking the token to
// any client that calls the API.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// Minimal AuthService stub for MED-03 tests
// ---------------------------------------------------------------------------

// med03AuthService is a no-op AuthService stub that returns a fixed user and
// verify token from Signup().
type med03AuthService struct {
	verifyToken string
}

func (s *med03AuthService) Signup(_ context.Context, req dto.SignupRequest) (*model.User, string, error) {
	return &model.User{ID: 1, Email: req.Email}, s.verifyToken, nil
}

func (s *med03AuthService) VerifyEmail(_ context.Context, _ string) error { return nil }
func (s *med03AuthService) Login(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
	return nil, nil
}
func (s *med03AuthService) AdminLogin(_ context.Context, _ dto.AdminLoginRequest) (*dto.LoginResponse, error) {
	return nil, nil
}
func (s *med03AuthService) RefreshTokens(_ context.Context, _ string) (*dto.RefreshResponse, error) {
	return nil, nil
}
func (s *med03AuthService) Logout(_ context.Context, _ uint) error { return nil }
func (s *med03AuthService) RequestPasswordReset(_ context.Context, _ string, _ *auth.AppContext) (string, error) {
	return "", nil
}
func (s *med03AuthService) ResetPassword(_ context.Context, _, _ string) error { return nil }
func (s *med03AuthService) ChangePassword(_ context.Context, _ uint, _, _ string) error {
	return nil
}
func (s *med03AuthService) ValidateInviteToken(_ context.Context, _ string) (*dto.InviteValidationResponse, error) {
	return nil, nil
}
func (s *med03AuthService) AcceptInvite(_ context.Context, _, _, _ string) (*dto.LoginResponse, error) {
	return nil, nil
}
func (s *med03AuthService) WithMFA(_ service.MFAService) service.AuthService { return s }
func (s *med03AuthService) AuthenticateAccount(context.Context, string, string, string) (*model.User, error) {
	return nil, errors.New("not used")
}

// ---------------------------------------------------------------------------
// Minimal UserService stub (unused by Signup handler but required by constructor)
// ---------------------------------------------------------------------------

type med03UserService struct{}

func (s *med03UserService) List(_ context.Context, _, _ int) ([]model.User, int64, error) {
	return nil, 0, nil
}
func (s *med03UserService) GetByID(_ context.Context, _ uint) (*model.User, error) { return nil, nil }
func (s *med03UserService) GetByEmail(_ context.Context, _ string) (*model.User, error) {
	return nil, nil
}
func (s *med03UserService) Create(_ context.Context, _ dto.CreateUserRequest) (*model.User, error) {
	return nil, nil
}
func (s *med03UserService) Update(_ context.Context, _ uint, _ dto.UpdateUserRequest) (*model.User, error) {
	return nil, nil
}
func (s *med03UserService) UpdateProfile(_ context.Context, _ uint, _ dto.UpdateProfileRequest) (*model.User, error) {
	return nil, nil
}
func (s *med03UserService) Delete(_ context.Context, _ uint) error                   { return nil }
func (s *med03UserService) VerifyEmail(_ context.Context, _ uint) error              { return nil }
func (s *med03UserService) UpdatePassword(_ context.Context, _ uint, _ string) error { return nil }
func (s *med03UserService) IncrementTokenVersion(_ context.Context, _ uint) error    { return nil }
func (s *med03UserService) RevokeTokens(_ context.Context, _ uint) error             { return nil }
func (s *med03UserService) Unlock(_ context.Context, _ uint) error                   { return nil }
func (s *med03UserService) ListSuperadmins(_ context.Context) ([]model.User, error)  { return nil, nil }
func (s *med03UserService) CountSuperadmins(_ context.Context) (int64, error)        { return 0, nil }
func (s *med03UserService) CreateSuperadmin(_ context.Context, _ dto.CreateSuperadminRequest) (*model.User, error) {
	return nil, nil
}
func (s *med03UserService) UpdateSuperadmin(_ context.Context, _ uint, _ dto.UpdateSuperadminRequest) (*model.User, error) {
	return nil, nil
}
func (s *med03UserService) DeleteSuperadmin(_ context.Context, _ uint, _ uint) error { return nil }
func (s *med03UserService) Block(_ context.Context, _ uint) error                    { return nil }

// ---------------------------------------------------------------------------
// Minimal EmailService stub
// ---------------------------------------------------------------------------

type med03EmailService struct{}

func (s *med03EmailService) SendVerificationEmail(_, _, _, _ string) error      { return nil }
func (s *med03EmailService) SendPasswordResetEmail(_, _, _, _ string) error     { return nil }
func (s *med03EmailService) SendInvitationEmail(_, _, _, _, _ string) error     { return nil }
func (s *med03EmailService) SendInviteEmail(_, _, _ string) error               { return nil }
func (s *med03EmailService) SendWelcomeEmail(_, _, _ string) error              { return nil }
func (s *med03EmailService) SendAppCredentialsEmail(_, _, _, _, _ string) error { return nil }
func (s *med03EmailService) SendMagicLinkEmail(_, _, _, _ string) error         { return nil }

// Compile-time interface checks.
var _ service.AuthService = (*med03AuthService)(nil)
var _ service.UserService = (*med03UserService)(nil)
var _ service.EmailService = (*med03EmailService)(nil)

// ---------------------------------------------------------------------------
// Helper: fire POST /api/auth/signup and return the decoded response
// ---------------------------------------------------------------------------

func med03Signup(t *testing.T, env string) dto.SignupResponse {
	t.Helper()

	authSvc := &med03AuthService{verifyToken: "test-verify-token-abc123"}
	h := NewAuthHandler(authSvc, &med03UserService{}, &med03EmailService{}, env, "https://auth.example.com")

	body := `{"email":"user@example.com","name":"Test User","password":"ValidPass1!","client_id":"app1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Signup(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Signup: expected 201, got %d (body: %s)", rr.Code, rr.Body.String())
	}

	var resp dto.SignupResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode SignupResponse: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// MED-03: environments that MUST NOT expose the verify URL
// ---------------------------------------------------------------------------

// TestMED03_ProductionEnv_NoVerifyURL verifies that ENV=production does NOT
// include the verify_url in the Signup response.
func TestMED03_ProductionEnv_NoVerifyURL(t *testing.T) {
	resp := med03Signup(t, "production")
	if resp.VerifyURL != "" {
		t.Errorf("MED-03: ENV=production must not include verify_url, got %q", resp.VerifyURL)
	}
}

// TestMED03_TestEnv_NoVerifyURL is the core regression guard: ENV=test was
// the old leaky condition.  After the fix it must NOT expose the token.
func TestMED03_TestEnv_NoVerifyURL(t *testing.T) {
	resp := med03Signup(t, "test")
	if resp.VerifyURL != "" {
		t.Errorf("MED-03: ENV=test must not include verify_url (was leaking before fix), got %q", resp.VerifyURL)
	}
}

// TestMED03_StagingEnv_NoVerifyURL verifies that a staging environment label
// also does not expose the token.
func TestMED03_StagingEnv_NoVerifyURL(t *testing.T) {
	resp := med03Signup(t, "staging")
	if resp.VerifyURL != "" {
		t.Errorf("MED-03: ENV=staging must not include verify_url, got %q", resp.VerifyURL)
	}
}

// TestMED03_EmptyEnv_NoVerifyURL verifies that an unset / empty environment
// (which defaults to "production" after MED-04) does not expose the token.
func TestMED03_EmptyEnv_NoVerifyURL(t *testing.T) {
	resp := med03Signup(t, "")
	if resp.VerifyURL != "" {
		t.Errorf("MED-03: empty ENV must not include verify_url, got %q", resp.VerifyURL)
	}
}

// ---------------------------------------------------------------------------
// MED-03: environments that SHOULD expose the verify URL (developer convenience)
// ---------------------------------------------------------------------------

// TestMED03_DevelopmentEnv_ExposesVerifyURL verifies that ENV=development
// includes the verify_url so developers can test the flow locally without
// a running mail server.
func TestMED03_DevelopmentEnv_ExposesVerifyURL(t *testing.T) {
	resp := med03Signup(t, "development")
	if resp.VerifyURL == "" {
		t.Error("MED-03: ENV=development should include verify_url for developer convenience")
	}
}

// TestMED03_DevEnv_ExposesVerifyURL verifies that the short alias "dev" is
// also accepted as a development environment indicator.
func TestMED03_DevEnv_ExposesVerifyURL(t *testing.T) {
	resp := med03Signup(t, "dev")
	if resp.VerifyURL == "" {
		t.Error("MED-03: ENV=dev should include verify_url for developer convenience")
	}
}

// TestMED03_DevelopmentEnv_VerifyURL_ContainsToken verifies that the exposed
// verify_url contains the actual verify token so it can be followed directly.
func TestMED03_DevelopmentEnv_VerifyURL_ContainsToken(t *testing.T) {
	resp := med03Signup(t, "development")
	if resp.VerifyURL == "" {
		t.Fatal("MED-03: verify_url is empty in development environment")
	}
	// The URL must contain the raw token so the developer can click it.
	const wantToken = "test-verify-token-abc123"
	if !strings.Contains(resp.VerifyURL, wantToken) {
		t.Errorf("MED-03: verify_url %q does not contain the verify token %q", resp.VerifyURL, wantToken)
	}
}

// TestMED03_DevelopmentEnv_VerifyURL_HasCorrectPrefix verifies that the
// verify_url is rooted at the configured issuer.
func TestMED03_DevelopmentEnv_VerifyURL_HasCorrectPrefix(t *testing.T) {
	resp := med03Signup(t, "development")
	if resp.VerifyURL == "" {
		t.Fatal("MED-03: verify_url is empty in development environment")
	}
	const wantPrefix = "https://auth.example.com/api/auth/verify-email"
	if !strings.HasPrefix(resp.VerifyURL, wantPrefix) {
		t.Errorf("MED-03: verify_url %q does not start with issuer prefix %q",
			resp.VerifyURL, wantPrefix)
	}
}
