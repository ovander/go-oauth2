package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
)

// Under PRIVILEGED_SCOPE_MODE=enforce, admin and monitoring:* go only to a
// client that lists them in allowed_scopes, or to an operator console, whatever
// SCOPE_POLICY_MODE says (an empty allowed_scopes does not grant them).
// observe audits and allows; off changes nothing.
func TestPrivilegedScopes(t *testing.T) {
	plain := &model.App{ID: 1, ClientID: "some-app"}
	listed := &model.App{ID: 2, ClientID: "ops-tool", AllowedScopes: model.StringArray{"openid", "monitoring:read"}}
	console := &model.App{ID: 3, ClientID: "admin-bff"}

	for _, tc := range []struct {
		name, mode, scopePolicy string
		app                     *model.App
		scope                   string
		refused, audited        bool
	}{
		{"off", "off", "off", plain, "openid admin", false, false},
		{"enforce, unlisted admin", "enforce", "off", plain, "openid admin", true, true},
		{"enforce, unlisted monitoring:write", "enforce", "off", plain, "monitoring:write", true, true},
		{"enforce, ordinary scopes", "enforce", "off", plain, "openid profile email api", false, false},
		{"enforce, listed scope", "enforce", "off", listed, "openid monitoring:read", false, false},
		{"enforce, listed and unlisted", "enforce", "off", listed, "monitoring:read monitoring:write", true, true},
		{"enforce, operator console", "enforce", "off", console, "openid admin monitoring:write", false, false},
		{"enforce, whatever the scope policy", "enforce", "enforce", plain, "admin", true, true},
		{"observe, unlisted admin", "observe", "off", plain, "admin", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := &captureAuditRepo{}
			s := &oauthService{auditRepo: audit, scopePolicyMode: tc.scopePolicy}
			s.SetPrivilegedScopePolicy(tc.mode, []string{"admin-bff", "monitoring-bff"})
			err := s.enforceClientScopes(context.Background(), tc.app, nil, "client_credentials", tc.scope)
			if refused := errors.Is(err, ErrScopeNotAllowed); refused != tc.refused || (err != nil && !refused) {
				t.Fatalf("err %v, want refused=%v", err, tc.refused)
			}
			if refused := errors.Is(err, ErrInvalidScope); tc.refused && !refused {
				t.Fatalf("a refusal must map to invalid_scope: %v", err)
			}
			got := audit.last != nil && audit.last.EventType == model.SecurityEventScopeDenied && audit.last.Details["reason"] == "privileged_scope"
			if got != tc.audited {
				t.Fatalf("audited %v, want %v (%+v)", got, tc.audited, audit.last)
			}
		})
	}
}
