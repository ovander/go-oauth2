// Package handler — tests for the admin step-up endpoint POST /api/admin/elevate
// (Tier-0 admin session hardening, PR4). It re-verifies the admin's credentials
// and returns a fresh-auth_time access token; without a wired reauthenticator it
// reports 501.
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/service"
)

type fakeReauth struct {
	resp *dto.LoginResponse
	err  error
}

func (f *fakeReauth) ReAuthenticate(_ context.Context, _ uint, _, _ string) (*dto.LoginResponse, error) {
	return f.resp, f.err
}

func newElevateHandler(reauth service.Reauthenticator) *AdminAuthHandler {
	h := NewAdminAuthHandler(&med03AuthService{}, &med03UserService{})
	if reauth != nil {
		h.SetReauthenticator(reauth)
	}
	return h
}

func postElevate(h *AdminAuthHandler, body string, withUser bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/admin/elevate", strings.NewReader(body))
	if withUser {
		r = r.WithContext(context.WithValue(r.Context(), contextkeys.UserIDKey, uint(7)))
	}
	rr := httptest.NewRecorder()
	h.Elevate(rr, r)
	return rr
}

func TestElevate_Success_ReturnsFreshToken(t *testing.T) {
	h := newElevateHandler(&fakeReauth{resp: &dto.LoginResponse{AccessToken: "fresh-at", TokenType: "Bearer", ExpiresIn: 900}})
	rr := postElevate(h, `{"password":"pw"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "fresh-at") {
		t.Errorf("expected the fresh access token in the body, got %q", rr.Body.String())
	}
}

func TestElevate_WrongPassword_401(t *testing.T) {
	h := newElevateHandler(&fakeReauth{err: service.ErrInvalidCredentials})
	if rr := postElevate(h, `{"password":"bad"}`, true); rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong password should be 401, got %d", rr.Code)
	}
}

func TestElevate_MFARequired_401(t *testing.T) {
	h := newElevateHandler(&fakeReauth{err: service.ErrMFARequired})
	rr := postElevate(h, `{"password":"pw"}`, true)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "mfa_required") {
		t.Errorf("MFA-enrolled admin should get 401 mfa_required, got %d %q", rr.Code, rr.Body.String())
	}
}

func TestElevate_MissingPassword_400(t *testing.T) {
	h := newElevateHandler(&fakeReauth{})
	if rr := postElevate(h, `{}`, true); rr.Code != http.StatusBadRequest {
		t.Errorf("missing password should be 400, got %d", rr.Code)
	}
}

func TestElevate_NoAuth_401(t *testing.T) {
	h := newElevateHandler(&fakeReauth{resp: &dto.LoginResponse{AccessToken: "x"}})
	if rr := postElevate(h, `{"password":"pw"}`, false); rr.Code != http.StatusUnauthorized {
		t.Errorf("missing user context should be 401, got %d", rr.Code)
	}
}

func TestElevate_NotConfigured_501(t *testing.T) {
	h := newElevateHandler(nil) // no reauthenticator wired
	if rr := postElevate(h, `{"password":"pw"}`, true); rr.Code != http.StatusNotImplemented {
		t.Errorf("unconfigured step-up should be 501, got %d", rr.Code)
	}
}
