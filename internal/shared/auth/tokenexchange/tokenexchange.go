// Package tokenexchange implements parsing and validation of OAuth 2.0 Token
// Exchange requests (RFC 8693) — the request side of delegation and
// impersonation (EPIC-16 / RFC-019). It is a standalone, side-effect-free
// primitive: it validates the protocol parameters and classifies the request,
// but does not itself mint or authorize any token. Wiring it into the token
// endpoint (and the policy that decides whether an exchange is permitted) are
// separate slices.
package tokenexchange

import (
	"errors"
	"net/url"
	"strings"
)

// GrantType is the RFC 8693 token-exchange grant type.
const GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// Token type URNs (RFC 8693 §3).
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

// Validation errors. All map to the RFC 8693 `invalid_request` token-endpoint
// error at the protocol layer.
var (
	ErrWrongGrantType             = errors.New("tokenexchange: grant_type is not token-exchange")
	ErrMissingSubjectToken        = errors.New("tokenexchange: subject_token is required")
	ErrMissingSubjectTokenType    = errors.New("tokenexchange: subject_token_type is required")
	ErrUnsupportedSubjectType     = errors.New("tokenexchange: unsupported subject_token_type")
	ErrUnsupportedRequestedType   = errors.New("tokenexchange: unsupported requested_token_type")
	ErrMissingActorTokenType      = errors.New("tokenexchange: actor_token_type is required when actor_token is present")
	ErrActorTokenTypeWithoutToken = errors.New("tokenexchange: actor_token_type given without actor_token")
	ErrUnsupportedActorType       = errors.New("tokenexchange: unsupported actor_token_type")
)

// Request is a validated RFC 8693 token-exchange request.
type Request struct {
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string // empty for impersonation
	ActorTokenType     string
	RequestedTokenType string // empty = server default (access token)
	Resource           []string
	Audience           []string
	Scope              string
}

// IsDelegation reports whether the request is a delegation (an actor_token is
// present, identifying the party acting on the subject's behalf). When false the
// request is an impersonation (the actor assumes the subject's identity).
func (r *Request) IsDelegation() bool { return r.ActorToken != "" }

// supportedSubjectTypes are the subject/actor token types this server can accept
// as input to an exchange. (JWT/ID-token/access-token are JWTs we can verify;
// refresh tokens are also issued by this server.)
var supportedInputTypes = map[string]bool{
	TokenTypeAccessToken:  true,
	TokenTypeRefreshToken: true,
	TokenTypeIDToken:      true,
	TokenTypeJWT:          true,
}

// supportedRequestedTypes are the token types a client may ask to receive.
var supportedRequestedTypes = map[string]bool{
	TokenTypeAccessToken:  true,
	TokenTypeRefreshToken: true,
	TokenTypeIDToken:      true,
	TokenTypeJWT:          true,
}

// Parse reads and validates a token-exchange request from form values (RFC 8693
// §2.1). It returns a typed sentinel error for each protocol violation. It does
// not verify the tokens themselves — that, and the authorization decision, are
// the caller's responsibility.
func Parse(v url.Values) (*Request, error) {
	if v.Get("grant_type") != GrantType {
		return nil, ErrWrongGrantType
	}

	subjectToken := strings.TrimSpace(v.Get("subject_token"))
	if subjectToken == "" {
		return nil, ErrMissingSubjectToken
	}
	subjectType := strings.TrimSpace(v.Get("subject_token_type"))
	if subjectType == "" {
		return nil, ErrMissingSubjectTokenType
	}
	if !supportedInputTypes[subjectType] {
		return nil, ErrUnsupportedSubjectType
	}

	actorToken := strings.TrimSpace(v.Get("actor_token"))
	actorType := strings.TrimSpace(v.Get("actor_token_type"))
	switch {
	case actorToken != "" && actorType == "":
		return nil, ErrMissingActorTokenType
	case actorToken == "" && actorType != "":
		return nil, ErrActorTokenTypeWithoutToken
	case actorToken != "" && !supportedInputTypes[actorType]:
		return nil, ErrUnsupportedActorType
	}

	requestedType := strings.TrimSpace(v.Get("requested_token_type"))
	if requestedType != "" && !supportedRequestedTypes[requestedType] {
		return nil, ErrUnsupportedRequestedType
	}

	return &Request{
		SubjectToken:       subjectToken,
		SubjectTokenType:   subjectType,
		ActorToken:         actorToken,
		ActorTokenType:     actorType,
		RequestedTokenType: requestedType,
		Resource:           v["resource"],
		Audience:           v["audience"],
		Scope:              strings.TrimSpace(v.Get("scope")),
	}, nil
}
