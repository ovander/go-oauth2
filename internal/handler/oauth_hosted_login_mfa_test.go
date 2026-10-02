package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
)

// HIGH-04: the hosted login (what the consoles and apps use) must let a user
// with MFA sign in: after the password it asks for the authentication code and
// passes it to Login. Before, it had no code field, so MFA users were locked out.

func mfaLoginPost(h *OAuthHandler, code string) *httptest.ResponseRecorder {
	const csrf = "mfa-csrf"
	form := url.Values{
		"client_id": {"app-1"}, "redirect_uri": {"https://app.example.com/cb"},
		"response_type": {"code"}, "csrf_token": {csrf},
		"email": {"alice@example.com"}, "password": {"right"},
	}
	if code != "" {
		form.Set("mfa_code", code)
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.7:4444"
	attachCSRFCookie(r, csrf)
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)
	return w
}

func mfaLoginHandler(defense loginDefense, gotCode *string, err error) *OAuthHandler {
	apps := &critAppService{getByClientID: func(_ context.Context, _ string) (*model.App, error) {
		return &model.App{ID: 1, ClientID: "app-1", Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}, Active: true}, nil
	}}
	authSvc := &critAuthService{login: func(_ context.Context, req dto.LoginRequest) (*dto.LoginResponse, error) {
		*gotCode = req.MFACode
		if err != nil {
			return nil, err
		}
		switch req.MFACode {
		case "":
			return nil, service.ErrMFARequired
		case "123456":
			return &dto.LoginResponse{UserID: 42}, nil
		default:
			return nil, service.ErrMFAInvalidCode
		}
	}}
	h := newCritTestHandler(apps, &critOAuthService{}, authSvc)
	h.autoDefense = defense
	return h
}

func TestHostedLogin_AsksForTheMFACode(t *testing.T) {
	d := &p35Defense{}
	var code string
	w := mfaLoginPost(mfaLoginHandler(d, &code, nil), "")
	if !strings.Contains(w.Body.String(), `name="mfa_code"`) {
		t.Fatalf("the page does not ask for the code:\n%s", w.Body.String())
	}
	if len(d.failed) != 0 {
		t.Errorf("a correct password awaiting its code was recorded as a failed login")
	}
}

func TestHostedLogin_PassesTheMFACode(t *testing.T) {
	d := &p35Defense{}
	var code string
	w := mfaLoginPost(mfaLoginHandler(d, &code, nil), " 123456 ")
	if code != "123456" {
		t.Fatalf("Login received mfa_code %q, want 123456", code)
	}
	if strings.Contains(w.Body.String(), `name="mfa_code"`) || len(d.succeeded) != 1 {
		t.Fatalf("sign-in with the code did not succeed (status %d)", w.Code)
	}

	d = &p35Defense{}
	w = mfaLoginPost(mfaLoginHandler(d, &code, nil), "000000")
	if !strings.Contains(w.Body.String(), `name="mfa_code"`) || len(d.failed) != 1 {
		t.Fatalf("a wrong code must re-ask and count as a failed login")
	}
}

func TestHostedLogin_AdminWithoutMFAUnderEnforce(t *testing.T) {
	var code string
	w := mfaLoginPost(mfaLoginHandler(&p35Defense{}, &code, service.ErrMFAEnrollmentRequired), "")
	if !strings.Contains(w.Body.String(), "multi-factor authentication enabled before signing in") {
		t.Fatalf("missing the enrollment message:\n%s", w.Body.String())
	}
}
