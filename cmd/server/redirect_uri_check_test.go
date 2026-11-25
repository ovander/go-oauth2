// Package main — REDIRECT_URI_MATCH_MODE wiring (#261): under enforce, the
// OAuth handler runs the OAuth service's exact-match check, which audits.
package main

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

func TestRedirectURICheckFor(t *testing.T) {
	// The real OAuth service, as bootstrap builds it, provides the check.
	svc := service.NewOAuthService(nil, nil, nil, nil, nil, nil, "https://issuer.example", nil, nil,
		"", 0, "", 0, "", "", "")
	svc.(interface{ SetRedirectURIMatchMode(string) }).SetRedirectURIMatchMode("enforce")

	for _, mode := range []string{"off", "observe", ""} {
		if check, err := redirectURICheckFor(mode, svc); check != nil || err != nil {
			t.Errorf("mode %q: a handler check is wired (err %v); only enforce wires one", mode, err)
		}
	}
	check, err := redirectURICheckFor("enforce", svc)
	if err != nil || check == nil {
		t.Fatalf("enforce: no handler check (err %v)", err)
	}
	app := &model.App{ID: 1, ClientID: "c", RedirectURIs: model.StringArray{"https://app.example.com/cb"}}
	if err := check(context.Background(), app, "https://app.example.com/cb/"); !errors.Is(err, auth.ErrRedirectURINotRegistered) {
		t.Errorf("enforce: a non-exact URI = %v, want ErrRedirectURINotRegistered", err)
	}
	if err := check(context.Background(), app, "https://app.example.com/cb"); err != nil {
		t.Errorf("enforce: the exact URI = %v", err)
	}

	// A service without the check fails bootstrap under enforce.
	if _, err := redirectURICheckFor("enforce", struct{}{}); err == nil {
		t.Error("enforce with a service lacking CheckRedirectURIExact: no error")
	}
}
