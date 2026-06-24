// Package handler — tests for the /api/admin/login deprecation flag (Tier-0
// admin session hardening, PR5). The password flow stays available by default
// (with a Deprecation header) but is refused once disabled.
package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postAdminLogin(h *AdminAuthHandler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Login(rr, r)
	return rr
}

func TestAdminLogin_Deprecation_HeaderAlwaysSet(t *testing.T) {
	h := NewAdminAuthHandler(&med03AuthService{}, &med03UserService{}) // enabled by default
	rr := postAdminLogin(h, `{"email":"a@b.c","password":"pw"}`)
	if rr.Header().Get("Deprecation") != "true" {
		t.Error("admin login should carry a Deprecation header (RFC 8594)")
	}
}

func TestAdminLogin_Disabled_Refused(t *testing.T) {
	h := NewAdminAuthHandler(&med03AuthService{}, &med03UserService{})
	h.SetPasswordLoginDisabled(true)
	rr := postAdminLogin(h, `{"email":"a@b.c","password":"pw"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("disabled password login should be 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "password_login_disabled") {
		t.Errorf("expected password_login_disabled code, got %q", rr.Body.String())
	}
}

func TestAdminLogin_EnabledByDefault_NotRefused(t *testing.T) {
	h := NewAdminAuthHandler(&med03AuthService{}, &med03UserService{})
	// med03AuthService.AdminLogin returns a response (not 403), so a non-403
	// status confirms the flag did not block the request.
	if rr := postAdminLogin(h, `{"email":"a@b.c","password":"pw"}`); rr.Code == http.StatusForbidden &&
		strings.Contains(rr.Body.String(), "password_login_disabled") {
		t.Error("password login must be enabled by default (zero value)")
	}
}
