// Package handler — tests for the admin change-password endpoint (Tier-0 admin
// session hardening, PR3). It satisfies a pending MustChangePassword flag and is
// exempt from the password-change enforcement middleware.
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/service"
)

// cpAuthService embeds the full med03 fake and makes ChangePassword's result
// configurable.
type cpAuthService struct {
	*med03AuthService
	changeErr error
}

func (s *cpAuthService) ChangePassword(_ context.Context, _ uint, _, _ string) error {
	return s.changeErr
}

func newChangePwHandler(changeErr error) *AdminAuthHandler {
	return NewAdminAuthHandler(&cpAuthService{med03AuthService: &med03AuthService{}, changeErr: changeErr}, &med03UserService{})
}

func postChangePw(h *AdminAuthHandler, body string, withUser bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/admin/change-password", strings.NewReader(body))
	if withUser {
		r = r.WithContext(context.WithValue(r.Context(), contextkeys.UserIDKey, uint(7)))
	}
	rr := httptest.NewRecorder()
	h.ChangePassword(rr, r)
	return rr
}

func TestChangePassword_Success(t *testing.T) {
	rr := postChangePw(newChangePwHandler(nil), `{"current_password":"old","new_password":"new-Str0ng!"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestChangePassword_WrongCurrent_401(t *testing.T) {
	rr := postChangePw(newChangePwHandler(service.ErrInvalidCredentials), `{"current_password":"bad","new_password":"new-Str0ng!"}`, true)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong current password should be 401, got %d", rr.Code)
	}
}

func TestChangePassword_MissingFields_400(t *testing.T) {
	rr := postChangePw(newChangePwHandler(nil), `{"current_password":""}`, true)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing fields should be 400, got %d", rr.Code)
	}
}

func TestChangePassword_NoAuth_401(t *testing.T) {
	rr := postChangePw(newChangePwHandler(nil), `{"current_password":"old","new_password":"new-Str0ng!"}`, false)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("missing user context should be 401, got %d", rr.Code)
	}
}
