package service

import (
	"errors"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/tokenexchange"
)

func delegationReq(scope string, aud ...string) *tokenexchange.Request {
	return &tokenexchange.Request{
		SubjectToken:     "subj",
		SubjectTokenType: tokenexchange.TokenTypeAccessToken,
		ActorToken:       "actor", // present -> delegation
		ActorTokenType:   tokenexchange.TokenTypeJWT,
		Scope:            scope,
		Audience:         aud,
	}
}

func impersonationReq(scope string, aud ...string) *tokenexchange.Request {
	return &tokenexchange.Request{
		SubjectToken:     "subj",
		SubjectTokenType: tokenexchange.TokenTypeAccessToken,
		// no actor -> impersonation
		Scope:    scope,
		Audience: aud,
	}
}

func TestAuthorizeExchange_DeniedWithoutCapability(t *testing.T) {
	app := &model.App{AllowTokenExchange: false}
	if _, err := authorizeExchange(app, delegationReq("read", "aud"), "read write"); !errors.Is(err, ErrExchangeNotAllowed) {
		t.Fatalf("want ErrExchangeNotAllowed, got %v", err)
	}
}

func TestAuthorizeExchange_DelegationAllowed(t *testing.T) {
	app := &model.App{AllowTokenExchange: true}
	dec, err := authorizeExchange(app, delegationReq("read", "https://api"), "read write")
	if err != nil {
		t.Fatalf("authorizeExchange: %v", err)
	}
	if dec.IsImpersonation {
		t.Fatal("actor present must be delegation")
	}
	if dec.GrantedScope != "read" {
		t.Fatalf("granted scope = %q, want read", dec.GrantedScope)
	}
}

func TestAuthorizeExchange_ImpersonationNeedsStrongerFlag(t *testing.T) {
	app := &model.App{AllowTokenExchange: true, AllowImpersonation: false}
	if _, err := authorizeExchange(app, impersonationReq("read", "aud"), "read write"); !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("want ErrImpersonationNotAllowed, got %v", err)
	}
}

func TestAuthorizeExchange_ImpersonationAllowedWithFlag(t *testing.T) {
	app := &model.App{AllowTokenExchange: true, AllowImpersonation: true}
	dec, err := authorizeExchange(app, impersonationReq("read", "aud"), "read write")
	if err != nil {
		t.Fatalf("authorizeExchange: %v", err)
	}
	if !dec.IsImpersonation {
		t.Fatal("no actor must be impersonation")
	}
}

func TestAuthorizeExchange_DownscopeOnly(t *testing.T) {
	app := &model.App{AllowTokenExchange: true}
	// admin is not in the subject's scope -> escalation rejected.
	if _, err := authorizeExchange(app, delegationReq("read admin", "aud"), "read write"); !errors.Is(err, ErrScopeNotSubset) {
		t.Fatalf("want ErrScopeNotSubset, got %v", err)
	}
}

func TestAuthorizeExchange_EmptyScopeDefaultsToSubject(t *testing.T) {
	app := &model.App{AllowTokenExchange: true}
	dec, err := authorizeExchange(app, delegationReq("", "aud"), "read write")
	if err != nil {
		t.Fatalf("authorizeExchange: %v", err)
	}
	if dec.GrantedScope != "read write" {
		t.Fatalf("granted scope = %q, want \"read write\"", dec.GrantedScope)
	}
}

func TestAuthorizeExchange_AudienceRequired(t *testing.T) {
	app := &model.App{AllowTokenExchange: true}
	if _, err := authorizeExchange(app, delegationReq("read"), "read write"); !errors.Is(err, ErrAudienceRequired) {
		t.Fatalf("want ErrAudienceRequired, got %v", err)
	}
}

func TestAuthorizeExchange_ResourceSatisfiesAudienceRequirement(t *testing.T) {
	app := &model.App{AllowTokenExchange: true}
	req := delegationReq("read")                       // no audience...
	req.Resource = []string{"https://api.example.com"} // ...but a resource is given
	if _, err := authorizeExchange(app, req, "read write"); err != nil {
		t.Fatalf("resource should satisfy the audience requirement: %v", err)
	}
}

func TestScopeIsSubset(t *testing.T) {
	cases := []struct {
		req, granted string
		want         bool
	}{
		{"", "read write", true},
		{"read", "read write", true},
		{"read write", "read write", true},
		{"admin", "read write", false},
		{"read admin", "read write", false},
	}
	for _, c := range cases {
		if got := scopeIsSubset(c.req, c.granted); got != c.want {
			t.Errorf("scopeIsSubset(%q,%q)=%v want %v", c.req, c.granted, got, c.want)
		}
	}
}
