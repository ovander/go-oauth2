package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// acr_values (OIDC Core §3.1.2.1) on /oauth/authorize: carried from the
// request through the login and consent pages to code issuance, bound into
// the consent token, and an unmet acr_values=mfa (ACR_VALUES_MODE=enforce)
// is answered unmet_authentication_requirements.

func TestAuthorize_AcrValuesIsCarriedByTheLoginPage(t *testing.T) {
	h := promptHandler()
	q := url.Values{
		"client_id": {"app-1"}, "redirect_uri": {"https://app.example.com/cb"},
		"response_type": {"code"}, "state": {"st-1"}, "scope": {"openid"},
		"code_challenge": {"abc"}, "code_challenge_method": {"S256"}, "acr_values": {"mfa"},
	}
	w := httptest.NewRecorder()
	h.Authorize(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if !strings.Contains(w.Body.String(), `name="acr_values" value="mfa"`) {
		t.Fatalf("the login page does not carry acr_values: %d", w.Code)
	}
}

func TestConsent_AcrValuesReachesAuthorizeAndIsBound(t *testing.T) {
	f := newBindingFixture()
	var got string
	f.h.oauthService = &critOAuthService{authorize: func(_ context.Context, req dto.AuthorizeRequest, _ uint) (string, error) {
		got = req.AcrValues
		f.authorized++
		return "the-code", nil
	}}
	form := consentForm()
	form.Set("acr_values", "mfa")
	form.Set("consent_token", boundConsentToken(t, 42, form, auth.AuthnEvidence{}))
	if f.post(form); f.authorized != 1 || got != "mfa" {
		t.Fatalf("authorized %d with acr_values %q, want one code asked with mfa", f.authorized, got)
	}

	// Dropping acr_values from the form after the page was shown is refused.
	dropped := consentForm()
	dropped.Set("acr_values", "mfa")
	dropped.Set("consent_token", boundConsentToken(t, 42, dropped, auth.AuthnEvidence{}))
	dropped.Del("acr_values")
	if w := f.post(dropped); f.authorized != 1 || strings.Contains(metaRefreshURL(w.Body.String()), "code=") {
		t.Fatalf("a form without its acr_values got a code (authorized %d)", f.authorized)
	}
}

func TestConsent_UnmetAcrValuesIsAnsweredToTheClient(t *testing.T) {
	f := newBindingFixture()
	f.h.oauthService = &critOAuthService{authorize: func(_ context.Context, _ dto.AuthorizeRequest, _ uint) (string, error) {
		return "", service.ErrACRValuesUnmet
	}}
	form := consentForm()
	form.Set("acr_values", "mfa")
	form.Set("consent_token", boundConsentToken(t, 42, form, auth.AuthnEvidence{}))
	target := metaRefreshURL(f.post(form).Body.String())
	if !strings.Contains(target, "error=unmet_authentication_requirements") || !strings.Contains(target, "state=st") {
		t.Fatalf("redirect %q, want error=unmet_authentication_requirements with the state", target)
	}
}
