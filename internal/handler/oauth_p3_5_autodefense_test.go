package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// P3-5: the hosted login form (POST /oauth/authorize, password path) must feed
// auto-defense exactly like POST /api/auth/login does.

type p35Defense struct {
	failed, succeeded []string
}

func (d *p35Defense) RecordFailedLogin(_ context.Context, ip, _ string) {
	d.failed = append(d.failed, ip)
}
func (d *p35Defense) RecordSuccessfulLogin(ip string) { d.succeeded = append(d.succeeded, ip) }

func p35Post(h *OAuthHandler, password string) *httptest.ResponseRecorder {
	const csrf = "p35-csrf"
	form := url.Values{
		"client_id": {"app-1"}, "redirect_uri": {"https://app.example.com/cb"},
		"response_type": {"code"}, "csrf_token": {csrf},
		"email": {"alice@example.com"}, "password": {password},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.7:4444"
	attachCSRFCookie(r, csrf)
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)
	return w
}

func p35Handler(defense loginDefense) *OAuthHandler {
	apps := &critAppService{getByClientID: func(_ context.Context, _ string) (*model.App, error) {
		return &model.App{ID: 1, ClientID: "app-1", Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}, Active: true}, nil
	}}
	authSvc := &critAuthService{login: func(_ context.Context, req dto.LoginRequest) (*dto.LoginResponse, error) {
		if req.Password == "right" {
			return &dto.LoginResponse{UserID: 42}, nil
		}
		return nil, service.ErrInvalidCredentials
	}}
	h := newCritTestHandler(apps, &critOAuthService{}, authSvc)
	h.autoDefense = defense
	return h
}

func TestP35_HostedLogin_FailureFeedsAutoDefense(t *testing.T) {
	d := &p35Defense{}
	h := p35Handler(d)
	p35Post(h, "wrong")
	if len(d.failed) != 1 || d.failed[0] != "203.0.113.7" {
		t.Fatalf("failed logins recorded = %v, want [203.0.113.7]", d.failed)
	}
	if len(d.succeeded) != 0 {
		t.Fatalf("unexpected success record %v", d.succeeded)
	}
}

func TestP35_HostedLogin_SuccessClearsAutoDefense(t *testing.T) {
	d := &p35Defense{}
	h := p35Handler(d)
	p35Post(h, "right")
	if len(d.succeeded) != 1 || d.succeeded[0] != "203.0.113.7" {
		t.Fatalf("successful logins recorded = %v, want [203.0.113.7]", d.succeeded)
	}
	if len(d.failed) != 0 {
		t.Fatalf("unexpected failure record %v", d.failed)
	}
}

func TestP35_HostedLogin_NilDefenseIsSafe(t *testing.T) {
	h := p35Handler(nil)
	h.SetAutoDefenseService(nil) // must not turn a typed nil into a non-nil interface
	if w := p35Post(h, "wrong"); w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (login page re-rendered)", w.Code)
	}
}
