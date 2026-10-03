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
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// ADMIN_APP_SIGNIN_POLICY=enforce: the refusal is shown on Socrate's own
// page, and the application never receives a code or a redirect for it.

func adminAppSignInHandler(authSvc *critAuthService, oauthSvc *critOAuthService) *OAuthHandler {
	apps := &critAppService{getByClientID: func(_ context.Context, _ string) (*model.App, error) {
		return &model.App{ID: 8, ClientID: "gpwa", Name: "GPWA", RedirectURIs: []string{"https://gpwa.example.com/cb"}, Active: true}, nil
	}}
	return newCritTestHandler(apps, oauthSvc, authSvc)
}

func TestAdminAppSignIn_HostedLoginShowsTheRefusal(t *testing.T) {
	authSvc := &critAuthService{login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
		return nil, service.ErrAdminAppSignInRefused
	}}
	h := adminAppSignInHandler(authSvc, &critOAuthService{})

	const csrf = "admin-app-csrf"
	form := url.Values{
		"client_id": {"gpwa"}, "redirect_uri": {"https://gpwa.example.com/cb"},
		"response_type": {"code"}, "csrf_token": {csrf}, "state": {"s"},
		"email": {"root@example.com"}, "password": {"pw"},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attachCSRFCookie(r, csrf)
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "can only sign in to the Socrate consoles") {
		t.Errorf("sign-in page does not explain the refusal; body = %q", body)
	}
	if strings.Contains(body, "You do not have access to this application") {
		t.Error("the generic no-access message is shown instead of the admin one")
	}
	if loc := metaRefreshURL(body); loc != "" {
		t.Errorf("redirected to %q; the refusal must stay on Socrate's page", loc)
	}
}

// A browser already signed in reaches code issuance through the consent step:
// the refusal is rendered there too, never sent to the app's redirect_uri.
func TestAdminAppSignIn_ConsentStepShowsTheRefusal(t *testing.T) {
	oauthSvc := &critOAuthService{authorize: func(_ context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
		return "", service.ErrAdminAppSignInRefused
	}}
	h := adminAppSignInHandler(&critAuthService{}, oauthSvc)

	consentToken, err := auth.IssueConsentToken(9, "gpwa", critTestSecretKey)
	if err != nil {
		t.Fatalf("IssueConsentToken: %v", err)
	}
	const csrf = "admin-app-consent-csrf"
	form := url.Values{
		"action": {"consent"}, "authorized": {"true"},
		"client_id": {"gpwa"}, "redirect_uri": {"https://gpwa.example.com/cb"},
		"response_type": {"code"}, "state": {"s"}, "csrf_token": {csrf}, "consent_token": {consentToken},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attachCSRFCookie(r, csrf)
	w := httptest.NewRecorder()
	h.AuthorizePost(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "can only sign in to the Socrate consoles") {
		t.Errorf("consent step does not explain the refusal; body = %q", body)
	}
	if loc := metaRefreshURL(body); loc != "" {
		t.Errorf("redirected to %q; the refusal must stay on Socrate's page", loc)
	}
}
