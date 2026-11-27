// Package handler — the consent token is bound to the authorization request
// it was shown for (#366): its redirect_uri, scope, PKCE challenge, nonce,
// max_age and prompt=login. A consent form edited after the page was rendered
// is refused, and prompt=login needs the sign-in of the login form.
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// boundConsentToken is the consent token the consent page would have carried
// for form: bound to the request the form submits.
func boundConsentToken(t *testing.T, userID uint, form url.Values, authn auth.AuthnEvidence) string {
	t.Helper()
	maxAge := -1
	if v, err := strconv.Atoi(form.Get("max_age")); err == nil && v >= 0 {
		maxAge = v
	}
	req := dto.AuthorizeRequest{
		ResponseType: form.Get("response_type"), ClientID: form.Get("client_id"), RedirectURI: form.Get("redirect_uri"),
		Scope: form.Get("scope"), State: form.Get("state"), Nonce: form.Get("nonce"),
		CodeChallenge: form.Get("code_challenge"), CodeChallengeMethod: form.Get("code_challenge_method"), MaxAge: maxAge,
	}
	token, err := auth.IssueConsentTokenForRequest(userID, req.ClientID, authn, consentRequestBinding(req, form.Get("prompt") == "login"), critTestSecretKey)
	if err != nil {
		t.Fatalf("IssueConsentTokenForRequest: %v", err)
	}
	return token
}

type bindingFixture struct {
	h          *OAuthHandler
	authorized int
}

func newBindingFixture() *bindingFixture {
	f := &bindingFixture{}
	app := &model.App{ClientID: "my-app", Name: "Test App", Active: true, RedirectURIs: model.StringArray{"https://app.example.com/cb", "https://app.example.com/cb2"}}
	appSvc := &critAppService{getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil }}
	oauthSvc := &critOAuthService{authorize: func(_ context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
		f.authorized++
		return "the-code", nil
	}}
	f.h = newCritTestHandler(appSvc, oauthSvc, &critAuthService{})
	return f
}

func consentForm() url.Values {
	return url.Values{
		"action": {"consent"}, "authorized": {"true"},
		"client_id": {"my-app"}, "redirect_uri": {"https://app.example.com/cb"}, "response_type": {"code"},
		"scope": {"openid profile"}, "state": {"st"}, "nonce": {"n-1"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
		"max_age": {"300"},
	}
}

func (f *bindingFixture) post(form url.Values) *httptest.ResponseRecorder {
	const csrf = "binding-csrf"
	form.Set("csrf_token", csrf)
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attachCSRFCookie(r, csrf)
	w := httptest.NewRecorder()
	f.h.AuthorizePost(w, r)
	return w
}

func TestConsent_TheRequestItWasShownForIsAccepted(t *testing.T) {
	f := newBindingFixture()
	form := consentForm()
	form.Set("consent_token", boundConsentToken(t, 42, form, auth.AuthnEvidence{}))
	w := f.post(form)
	if f.authorized != 1 || !strings.Contains(metaRefreshURL(w.Body.String()), "code=the-code") {
		t.Fatalf("unchanged consent form: authorized %d, status %d", f.authorized, w.Code)
	}
}

// Any parameter changed after the consent page was rendered is refused, and
// no code is issued.
func TestConsent_AnEditedFormIsRefused(t *testing.T) {
	for name, edit := range map[string]func(url.Values){
		"widened scope":       func(v url.Values) { v.Set("scope", "openid profile admin") },
		"another challenge":   func(v url.Values) { v.Set("code_challenge", "another-challenge-another-challenge-another1") },
		"challenge dropped":   func(v url.Values) { v.Del("code_challenge"); v.Del("code_challenge_method") },
		"challenge method":    func(v url.Values) { v.Set("code_challenge_method", "plain") },
		"max_age dropped":     func(v url.Values) { v.Del("max_age") },
		"max_age widened":     func(v url.Values) { v.Set("max_age", "86400") },
		"another nonce":       func(v url.Values) { v.Set("nonce", "n-2") },
		"another state":       func(v url.Values) { v.Set("state", "st-2") },
		"another response":    func(v url.Values) { v.Set("response_type", "token") },
		"prompt=login added":  func(v url.Values) { v.Set("prompt", "login") },
		"redirect_uri change": func(v url.Values) { v.Set("redirect_uri", "https://app.example.com/cb2") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newBindingFixture()
			form := consentForm()
			form.Set("consent_token", boundConsentToken(t, 42, form, auth.AuthnEvidence{}))
			edit(form)
			w := f.post(form)
			if f.authorized != 0 {
				t.Fatalf("a code was issued for an edited form (status %d)", w.Code)
			}
			if !strings.Contains(w.Body.String(), "changed after the consent page was shown") {
				t.Errorf("edited form not refused as such: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

// A consent token without a request binding is refused (fail closed).
func TestConsent_AnUnboundTokenIsRefused(t *testing.T) {
	f := newBindingFixture()
	form := consentForm()
	token, err := auth.IssueConsentToken(42, "my-app", critTestSecretKey)
	if err != nil {
		t.Fatal(err)
	}
	form.Set("consent_token", token)
	w := f.post(form)
	if f.authorized != 0 || !strings.Contains(w.Body.String(), "changed after the consent page was shown") {
		t.Fatalf("unbound consent token: authorized %d, status %d", f.authorized, w.Code)
	}
}

// prompt=login needs the sign-in of the login form: a consent token from a
// session that was already signed in (no auth_time) gets login_required.
func TestConsent_PromptLoginNeedsTheLoginForm(t *testing.T) {
	f := newBindingFixture()
	form := consentForm()
	form.Set("prompt", "login")
	form.Set("consent_token", boundConsentToken(t, 42, form, auth.AuthnEvidence{}))
	w := f.post(form)
	if f.authorized != 0 || !strings.Contains(metaRefreshURL(w.Body.String()), "error=login_required") {
		t.Fatalf("prompt=login without a sign-in: authorized %d, body %s", f.authorized, w.Body.String())
	}

	g := newBindingFixture()
	form = consentForm()
	form.Set("prompt", "login")
	form.Set("consent_token", boundConsentToken(t, 42, form, auth.AuthnEvidence{AuthTime: time.Now().Unix(), AMR: []string{"pwd"}}))
	w = g.post(form)
	if g.authorized != 1 || !strings.Contains(metaRefreshURL(w.Body.String()), "code=the-code") {
		t.Fatalf("prompt=login after the login form: authorized %d, status %d", g.authorized, w.Code)
	}
}

// The login page carries prompt=login to the consent step.
func TestAuthorize_PromptLoginIsCarriedByTheLoginPage(t *testing.T) {
	f := newBindingFixture()
	target := "/oauth/authorize?response_type=code&client_id=my-app&prompt=login" +
		"&redirect_uri=" + url.QueryEscape("https://app.example.com/cb") + "&state=st"
	w := httptest.NewRecorder()
	f.h.Authorize(w, httptest.NewRequest(http.MethodGet, target, nil))
	if !strings.Contains(w.Body.String(), `name="prompt" value="login"`) {
		t.Fatalf("the login page does not carry prompt=login: %d", w.Code)
	}
	// Without prompt=login, it carries nothing.
	w = httptest.NewRecorder()
	f.h.Authorize(w, httptest.NewRequest(http.MethodGet, strings.Replace(target, "&prompt=login", "", 1), nil))
	if strings.Contains(w.Body.String(), `name="prompt"`) {
		t.Fatal("the login page carries a prompt that was not asked for")
	}
}

// After the login form of a prompt=login request, the consent page carries
// prompt=login and a consent token bound to it, whose submission is accepted.
func TestAuthorizePost_PromptLoginReachesTheConsentStep(t *testing.T) {
	f := newBindingFixture()
	authSvc := &critAuthService{login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
		return &dto.LoginResponse{UserID: 42, AuthTime: time.Now().Unix(), AMR: []string{"pwd"}}, nil
	}}
	f.h.authService = authSvc
	form := consentForm()
	form.Del("action")
	form.Del("authorized")
	form.Set("prompt", "login")
	form.Set("email", "u@example.test")
	form.Set("password", "pw")
	w := f.post(form)
	body := w.Body.String()
	if !strings.Contains(body, `name="prompt" value="login"`) {
		t.Fatalf("the consent page does not carry prompt=login: %d", w.Code)
	}
	const marker = `name="consent_token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no consent token on the consent page")
	}
	token := body[i+len(marker):]
	token = token[:strings.Index(token, `"`)]

	submit := consentForm()
	submit.Set("prompt", "login")
	submit.Set("consent_token", token)
	w = f.post(submit)
	if f.authorized != 1 || !strings.Contains(metaRefreshURL(w.Body.String()), "code=the-code") {
		t.Fatalf("consent after the prompt=login sign-in: authorized %d, status %d", f.authorized, w.Code)
	}
}

// A prompt value the GET refuses is refused on the POST too.
func TestAuthorizePost_InvalidPromptIsRefused(t *testing.T) {
	f := newBindingFixture()
	form := consentForm()
	form.Set("prompt", "none login")
	form.Set("consent_token", boundConsentToken(t, 42, form, auth.AuthnEvidence{}))
	w := f.post(form)
	if f.authorized != 0 || !strings.Contains(w.Body.String(), "prompt=none cannot be combined") {
		t.Fatalf("prompt=none login on the POST: authorized %d, status %d", f.authorized, w.Code)
	}
}

// The sign-in on the login page is marked as made in this request: the code
// is asked for with that evidence, which satisfies max_age=0 (step-up).
func TestAuthorizePost_TheLoginFormSignInIsInTheRequest(t *testing.T) {
	f := newBindingFixture()
	var got auth.AuthnEvidence
	f.h.oauthService = &critOAuthService{authorize: func(ctx context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
		got = service.AuthnEvidenceFrom(ctx)
		f.authorized++
		return "the-code", nil
	}}
	signedIn := time.Now().Unix()
	f.h.authService = &critAuthService{login: func(_ context.Context, _ dto.LoginRequest) (*dto.LoginResponse, error) {
		return &dto.LoginResponse{UserID: 42, AuthTime: signedIn, AMR: []string{"pwd", "otp", "mfa"}, ACR: "mfa"}, nil
	}}
	form := consentForm()
	form.Del("action")
	form.Del("authorized")
	form.Set("max_age", "0")
	form.Set("email", "u@example.test")
	form.Set("password", "pw")
	body := f.post(form).Body.String()
	const marker = `name="consent_token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no consent token on the consent page")
	}
	token := body[i+len(marker):]
	token = token[:strings.Index(token, `"`)]

	submit := consentForm()
	submit.Set("max_age", "0")
	submit.Set("consent_token", token)
	f.post(submit)
	if f.authorized != 1 || !got.InRequest || got.AuthTime != signedIn || got.ACR != "mfa" {
		t.Fatalf("authorized %d with evidence %+v, want one code with the in-request sign-in", f.authorized, got)
	}
}

// Evidence that does not come from the login form is not in the request.
func TestConsent_AnEarlierSignInIsNotInTheRequest(t *testing.T) {
	f := newBindingFixture()
	var got auth.AuthnEvidence
	f.h.oauthService = &critOAuthService{authorize: func(ctx context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
		got = service.AuthnEvidenceFrom(ctx)
		return "the-code", nil
	}}
	form := consentForm()
	form.Set("consent_token", boundConsentToken(t, 42, form, auth.AuthnEvidence{}))
	f.post(form)
	if got.InRequest {
		t.Fatalf("evidence %+v from a signed-in session is marked in the request", got)
	}
}
