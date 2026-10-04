package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

var consentTokenField = regexp.MustCompile(`name="consent_token"\s+value="([^"]+)"`)

// Hosted login → consent → code: the sign-in that just happened (when, and
// with which methods) is signed into the consent token and handed to
// Authorize, so the code's tokens report it.
func TestHostedLogin_SignInEvidenceReachesAuthorize(t *testing.T) {
	ev := auth.AuthnEvidence{AuthTime: 1791000000, AMR: []string{"pwd", "otp", "mfa"}, ACR: "mfa"}
	apps := &critAppService{getByClientID: func(_ context.Context, _ string) (*model.App, error) {
		return &model.App{ID: 1, ClientID: "app-1", Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}, Active: true}, nil
	}}
	authSvc := &critAuthService{login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
		return &dto.LoginResponse{UserID: 42, AuthTime: ev.AuthTime, AMR: ev.AMR, ACR: ev.ACR}, nil
	}}
	var got auth.AuthnEvidence
	oauthSvc := &critOAuthService{authorize: func(ctx context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
		got = service.AuthnEvidenceFrom(ctx)
		return "code-1", nil
	}}
	h := newCritTestHandler(apps, oauthSvc, authSvc)

	post := func(form url.Values, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		attachCSRFCookie(r, csrf)
		w := httptest.NewRecorder()
		h.AuthorizePost(w, r)
		return w
	}
	base := url.Values{"client_id": {"app-1"}, "redirect_uri": {"https://app.example.com/cb"}, "response_type": {"code"}, "state": {"s"}}

	login := url.Values{"csrf_token": {"c1"}, "email": {"ada@example.test"}, "password": {"pw"}}
	for k, v := range base {
		login[k] = v
	}
	m := consentTokenField.FindStringSubmatch(post(login, "c1").Body.String())
	if m == nil {
		t.Fatal("consent page has no consent_token")
	}
	_, _, signed, err := auth.ValidateConsentTokenWithAuthn(m[1], critTestSecretKey)
	if err != nil || !reflect.DeepEqual(signed, ev) {
		t.Fatalf("consent token evidence = %+v, %v; want %+v", signed, err, ev)
	}

	consent := url.Values{"action": {"consent"}, "authorized": {"true"}, "csrf_token": {"c2"}, "consent_token": {m[1]}}
	for k, v := range base {
		consent[k] = v
	}
	post(consent, "c2")
	if !reflect.DeepEqual(got, ev) {
		t.Fatalf("Authorize got evidence %+v, want %+v", got, ev)
	}
}
