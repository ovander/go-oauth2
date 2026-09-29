package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/service"
)

// mfaLoginAuthService embeds the no-op med03AuthService (which already satisfies
// service.AuthService) and overrides Login/AdminLogin to return an injectable
// error, so we can assert the handlers' MFA error → HTTP status mapping.
type mfaLoginAuthService struct {
	med03AuthService
	loginErr error
	adminErr error
}

func (m *mfaLoginAuthService) Login(context.Context, dto.LoginRequest) (*dto.LoginResponse, error) {
	return nil, m.loginErr
}
func (m *mfaLoginAuthService) AdminLogin(context.Context, dto.AdminLoginRequest) (*dto.LoginResponse, error) {
	return nil, m.adminErr
}

var _ service.AuthService = (*mfaLoginAuthService)(nil)

func TestAuthHandler_Login_MFARequired(t *testing.T) {
	h := NewAuthHandler(&mfaLoginAuthService{loginErr: service.ErrMFARequired}, nil, nil, "test", "https://issuer")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"email":"a@b.com","password":"x","app_client_id":"app"}`))
	h.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "mfa_required") {
		t.Fatalf("expected an mfa_required body, got %q", rr.Body.String())
	}
}

func TestAuthHandler_Login_MFAInvalidCode(t *testing.T) {
	h := NewAuthHandler(&mfaLoginAuthService{loginErr: service.ErrMFAInvalidCode}, nil, nil, "test", "https://issuer")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"email":"a@b.com","password":"x","app_client_id":"app","mfa_code":"000000"}`))
	h.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid mfa code") {
		t.Fatalf("expected an invalid-mfa-code body, got %q", rr.Body.String())
	}
}

func TestAdminAuthHandler_Login_MFARequired(t *testing.T) {
	h := NewAdminAuthHandler(&mfaLoginAuthService{adminErr: service.ErrMFARequired}, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login",
		strings.NewReader(`{"email":"a@b.com","password":"x"}`))
	h.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "mfa_required") {
		t.Fatalf("expected an mfa_required body, got %q", rr.Body.String())
	}
}

func TestAdminAuthHandler_Login_MFAEnrollmentRequired(t *testing.T) {
	h := NewAdminAuthHandler(&mfaLoginAuthService{adminErr: service.ErrMFAEnrollmentRequired}, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login",
		strings.NewReader(`{"email":"a@b.com","password":"x"}`))
	h.Login(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "mfa_enrollment_required") {
		t.Fatalf("expected an mfa_enrollment_required body, got %q", rr.Body.String())
	}
}
