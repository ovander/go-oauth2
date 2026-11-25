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
)

func TestAuthorize_ExactRedirectURIUnderEnforce(t *testing.T) {
	app := &model.App{ClientID: "my-app", Name: "Test App", Active: true, RedirectURIs: model.StringArray{"https://app.example.com/cb"}}
	appSvc := &critAppService{getByClientID: func(_ context.Context, _ string) (*model.App, error) { return app, nil }}
	page := func(exact bool, redirectURI string) string {
		h := newCritTestHandler(appSvc, &critOAuthService{}, &critAuthService{})
		h.SetRedirectURIExactMatch(exact)
		target := "/oauth/authorize?response_type=code&client_id=my-app&state=s&redirect_uri=" + url.QueryEscape(redirectURI)
		w := httptest.NewRecorder()
		h.Authorize(w, httptest.NewRequest(http.MethodGet, target, nil))
		return w.Body.String()
	}
	const inexact = "https://app.example.com/cb/"
	if body := page(false, inexact); strings.Contains(body, "not registered") {
		t.Fatal("off: a normalized match was refused")
	}
	if body := page(true, inexact); !strings.Contains(body, "not registered") {
		t.Fatalf("enforce: a normalized-only match was not refused: %.200s", body)
	}
	if body := page(true, "https://app.example.com/cb"); strings.Contains(body, "not registered") {
		t.Fatal("enforce: the exact registered URI was refused")
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
	logout := func(exact bool, uri string) *httptest.ResponseRecorder {
		h := newTestEndSessionHandler(appSvc, &mockOAuthService{})
		h.SetRedirectURIExactMatch(exact)
		w := httptest.NewRecorder()
		h.EndSession(w, httptest.NewRequest(http.MethodGet, "/oauth/logout?client_id=good-client&post_logout_redirect_uri="+url.QueryEscape(uri), nil))
		return w
	}
	const inexact = "https://app.example.com/logout/"
	if w := logout(false, inexact); w.Code != http.StatusFound {
		t.Fatalf("off: a normalized match did not redirect (%d)", w.Code)
	}
	if w := logout(true, inexact); w.Code == http.StatusFound {
		t.Fatalf("enforce: redirected to a normalized-only match: %s", w.Header().Get("Location"))
	}
	if w := logout(true, registered); w.Code != http.StatusFound || w.Header().Get("Location") != registered {
		t.Fatalf("enforce: the exact URI did not redirect (%d %s)", w.Code, w.Header().Get("Location"))
	}
}
