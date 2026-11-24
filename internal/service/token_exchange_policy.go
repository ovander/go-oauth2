package service

import (
	"errors"
	"strings"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth/tokenexchange"
)

// Token-exchange authorization errors (RFC 8693 / EPIC-16). They encode the
// best-practice policy: default-deny, delegation-preferred, downscope-only, and
// audience-bound output.
var (
	// ErrExchangeNotAllowed: the client is not permitted to use the
	// token-exchange grant at all (allow_token_exchange is false).
	ErrExchangeNotAllowed = errors.New("token exchange not permitted for this client")
	// ErrImpersonationNotAllowed: the request is an impersonation (no actor
	// token) and the client lacks allow_impersonation.
	ErrImpersonationNotAllowed = errors.New("impersonation not permitted for this client")
	// ErrScopeNotSubset: the requested scope is not a subset of the subject's
	// granted scope (privilege escalation is never allowed).
	ErrScopeNotSubset = errors.New("requested scope exceeds the subject's scope")
	// ErrAudienceRequired: no target audience/resource was given. Exchanged
	// tokens must be bound to a specific audience, never general-purpose.
	ErrAudienceRequired = errors.New("token exchange requires a target audience or resource")
	// ErrAudienceNotAllowed: a requested audience or resource is not one of
	// the requesting client's registered audiences.
	ErrAudienceNotAllowed = errors.New("requested audience or resource is not registered for this client")
)

// ExchangeDecision is the result of an authorized token-exchange request: the
// (possibly downscoped) scope to mint, the bound audience, and whether the
// exchange is an impersonation (no actor) vs a delegation.
type ExchangeDecision struct {
	GrantedScope    string
	Audience        []string
	IsImpersonation bool
}

// authorizeExchange applies the token-exchange authorization policy. It is a
// pure decision function — it does not verify tokens, mint anything, or touch
// the database; the caller supplies the requesting client, the parsed request,
// and the subject's currently granted scope. It enforces:
//
//   - default-deny: the client must have allow_token_exchange;
//   - impersonation (no actor_token) additionally requires allow_impersonation;
//   - downscope-only: the requested scope must be a subset of the subject's
//     scope (an empty request scope defaults to the subject's scope);
//   - audience-bound: a target audience or resource must be present, and each
//     one must be among the client's registered audiences (app.Audiences, set
//     by an operator); the exchanged token's aud is the requested audiences
//     and resources together.
func authorizeExchange(app *model.App, req *tokenexchange.Request, subjectScope string) (*ExchangeDecision, error) {
	if !app.AllowTokenExchange {
		return nil, ErrExchangeNotAllowed
	}
	isImpersonation := !req.IsDelegation()
	if isImpersonation && !app.AllowImpersonation {
		return nil, ErrImpersonationNotAllowed
	}

	if len(req.Audience) == 0 && len(req.Resource) == 0 {
		return nil, ErrAudienceRequired
	}
	registered := make(map[string]struct{}, len(app.Audiences))
	for _, a := range app.Audiences {
		registered[a] = struct{}{}
	}
	var targets []string
	seen := make(map[string]struct{})
	for _, t := range append(append([]string{}, req.Audience...), req.Resource...) {
		if _, ok := registered[t]; !ok {
			return nil, ErrAudienceNotAllowed
		}
		if _, dup := seen[t]; !dup {
			seen[t] = struct{}{}
			targets = append(targets, t)
		}
	}

	granted := strings.TrimSpace(req.Scope)
	if granted == "" {
		granted = subjectScope
	} else if !scopeIsSubset(granted, subjectScope) {
		return nil, ErrScopeNotSubset
	}

	return &ExchangeDecision{
		GrantedScope:    granted,
		Audience:        targets,
		IsImpersonation: isImpersonation,
	}, nil
}

// scopeIsSubset reports whether every space-delimited scope token in requested
// is also present in granted.
func scopeIsSubset(requested, granted string) bool {
	grantedSet := make(map[string]struct{})
	for _, s := range strings.Fields(granted) {
		grantedSet[s] = struct{}{}
	}
	for _, s := range strings.Fields(requested) {
		if _, ok := grantedSet[s]; !ok {
			return false
		}
	}
	return true
}
