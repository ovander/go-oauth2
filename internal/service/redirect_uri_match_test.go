// Package service — REDIRECT_URI_MATCH_MODE (#261, RFC 9700 §2.1): a
// redirect_uri that matches a registered one only after normalization is
// accepted as before under off, audited under observe, refused under enforce.
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// inexactRedirect matches the registered "http://localhost:5173/auth/callback"
// only after normalization (scheme case, trailing slash).
const inexactRedirect = "HTTP://localhost:5173/auth/callback/"

func TestAuthorize_RedirectURIMatchMode(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		redirectURI string
		wantCode    bool
		wantAudit   bool
	}{
		{"off", inexactRedirect, true, false},
		{"observe", inexactRedirect, true, true},
		{"enforce", inexactRedirect, false, true},
		{"enforce", "http://localhost:5173/auth/callback", true, false},
	} {
		t.Run(tc.mode+" "+tc.redirectURI, func(t *testing.T) {
			admin := &model.User{ID: 42, Email: "admin@example.com", IsVerified: true, Role: model.UserRoleSuperadmin}
			svc := newAuthorizeSvc(t, admin)
			audit := &countingAuditRepo{}
			svc.auditRepo = audit
			svc.SetRedirectURIMatchMode(tc.mode)
			req := authorizeReq()
			req.RedirectURI = tc.redirectURI

			code, err := svc.Authorize(context.Background(), req, admin.ID)
			if tc.wantCode && (err != nil || code == "") {
				t.Fatalf("Authorize = %q, %v; want a code", code, err)
			}
			if !tc.wantCode && !errors.Is(err, ErrInvalidRedirectURI) {
				t.Fatalf("Authorize = %q, %v; want ErrInvalidRedirectURI", code, err)
			}
			got := audit.count(model.SecurityEventRedirectURIInexact)
			if tc.wantAudit != (got == 1) || got > 1 {
				t.Fatalf("redirect_uri_inexact_match events = %d, want audit %v", got, tc.wantAudit)
			}
			if tc.wantAudit {
				ev := audit.lastOf(model.SecurityEventRedirectURIInexact)
				if ev.Details["redirect_uri"] != tc.redirectURI || ev.Details["mode"] != tc.mode || ev.AppID == nil {
					t.Errorf("audit details = %+v", ev)
				}
			}
		})
	}
}

// CheckRedirectURIExact is what the OAuth handler runs before sign-in under
// enforce: the refusal is audited there too, with no user yet.
func TestCheckRedirectURIExact_AuditsTheRefusal(t *testing.T) {
	app := &model.App{ID: 3, ClientID: "my-app", RedirectURIs: model.StringArray{"http://localhost:5173/auth/callback"}}
	for _, tc := range []struct {
		mode, uri string
		wantErr   bool
		wantAudit bool
	}{
		{"enforce", inexactRedirect, true, true},
		{"enforce", "http://localhost:5173/auth/callback", false, false},
		{"observe", inexactRedirect, false, true},
		{"off", inexactRedirect, false, false},
	} {
		svc := &oauthService{}
		audit := &countingAuditRepo{}
		svc.auditRepo = audit
		svc.SetRedirectURIMatchMode(tc.mode)
		err := svc.CheckRedirectURIExact(context.Background(), app, tc.uri)
		if tc.wantErr != errors.Is(err, auth.ErrRedirectURINotRegistered) || (!tc.wantErr && err != nil) {
			t.Errorf("%s %s: err = %v, want refused %v", tc.mode, tc.uri, err, tc.wantErr)
		}
		got := audit.count(model.SecurityEventRedirectURIInexact)
		if tc.wantAudit != (got == 1) || got > 1 {
			t.Errorf("%s %s: %d redirect_uri_inexact_match events, want audit %v", tc.mode, tc.uri, got, tc.wantAudit)
		}
		if tc.wantAudit {
			if ev := audit.lastOf(model.SecurityEventRedirectURIInexact); ev.UserID != nil || ev.AppID == nil || *ev.AppID != app.ID {
				t.Errorf("%s: audit = %+v, want the app and no user", tc.mode, ev)
			}
		}
	}
}
