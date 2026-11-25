// Package handler — REDIRECT_URI_MATCH_MODE enforce (#261): the authorize
// page and the post-logout redirect require the exact registered redirect_uri.
package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// exactCheck stands for the service's CheckRedirectURIExact under enforce:
// it refuses a URI that is not exactly registered, and counts the refusals
// (the service audits each one).
type exactCheck struct{ refused int }

func (c *exactCheck) check(_ context.Context, app *model.App, uri string) error {
	if !auth.RedirectURIExactlyRegistered(uri, app.RedirectURIs) {
		c.refused++
		return auth.ErrRedirectURINotRegistered
	}
	return nil
}

func TestAuthorize_ExactRedirectURIUnderEnforce(t *testing.T) {
	app := &model.App{ClientID: "my-app", Name: "Test App", Active: true, RedirectURIs: model.StringArray{"https://app.example.com/cb"}}
	appSvc := &critAppService{getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil }}
	checks := &exactCheck{}
	page := func(exact bool, redirectURI string) *httptest.ResponseRecorder {
		h := newCritTestHandler(appSvc, &critOAuthService{}, &critAuthService{})
		if exact {
			h.SetRedirectURICheck(checks.check)
		}
		target := "/oauth/authorize?response_type=code&client_id=my-app&state=s&redirect_uri=" + url.QueryEscape(redirectURI)
		w := httptest.NewRecorder()
		h.Authorize(w, httptest.NewRequest(http.MethodGet, target, nil))
		return w
	}
	// signInPage reports whether w is the sign-in form of an accepted request.
	signInPage := func(w *httptest.ResponseRecorder) bool {
		body := w.Body.String()
		return w.Code == http.StatusOK && strings.Contains(body, `name="csrf_token"`) && !strings.Contains(body, "not registered")
	}
	const inexact = "https://app.example.com/cb/"
	if w := page(false, inexact); !signInPage(w) {
		t.Fatalf("off: a normalized match did not get the sign-in page (%d)", w.Code)
	}
	if w := page(true, inexact); signInPage(w) || !strings.Contains(w.Body.String(), "not registered") {
		t.Fatalf("enforce: a normalized-only match was not refused as unregistered: %d %.200s", w.Code, w.Body.String())
	}
	if w := page(true, "https://app.example.com/cb"); !signInPage(w) {
		t.Fatalf("enforce: the exact registered URI did not get the sign-in page (%d)", w.Code)
	}
	if checks.refused != 1 {
		t.Errorf("the service check refused %d URIs, want 1: the refusal must go through it, to be audited", checks.refused)
	}
}

func TestEndSession_ExactPostLogoutURIUnderEnforce(t *testing.T) {
	registered := "https://app.example.com/logout"
	appSvc := &mockAppService{getByClientID: func(_ context.Context, clientID string) (*model.App, error) {
		if clientID != "good-client" {
			return nil, fmt.Errorf("not found")
		}
		return &model.App{ClientID: "good-client", RedirectURIs: model.StringArray{registered}}, nil
	}}
	checks := &exactCheck{}
	logout := func(exact bool, uri string) *httptest.ResponseRecorder {
		h := newTestEndSessionHandler(appSvc, &mockOAuthService{})
		if exact {
			h.SetRedirectURICheck(checks.check)
		}
		w := httptest.NewRecorder()
		h.EndSession(w, httptest.NewRequest(http.MethodGet, "/oauth/logout?client_id=good-client&post_logout_redirect_uri="+url.QueryEscape(uri), nil))
		return w
	}
	const inexact = "https://app.example.com/logout/"
	if w := logout(false, inexact); w.Code != http.StatusFound {
		t.Fatalf("off: a normalized match did not redirect (%d)", w.Code)
	}
	// A refused post_logout_redirect_uri is not an error: the logout
	// completes, answered in JSON instead of a redirect.
	if w := logout(true, inexact); w.Code != http.StatusOK || w.Header().Get("Location") != "" {
		t.Fatalf("enforce: a normalized-only match = %d (Location %q), want the 200 JSON answer", w.Code, w.Header().Get("Location"))
	}
	if w := logout(true, registered); w.Code != http.StatusFound || w.Header().Get("Location") != registered {
		t.Fatalf("enforce: the exact URI did not redirect (%d %s)", w.Code, w.Header().Get("Location"))
	}
	if checks.refused != 1 {
		t.Errorf("the service check refused %d URIs, want 1", checks.refused)
	}
}
