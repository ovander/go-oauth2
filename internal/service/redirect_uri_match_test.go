// Package service — REDIRECT_URI_MATCH_MODE (#261, RFC 9700 §2.1): a
// redirect_uri that matches a registered one only after normalization is
// accepted as before under off, audited under observe, refused under enforce.
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
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
