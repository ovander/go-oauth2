package tokenexchange

import (
	"errors"
	"net/url"
	"testing"
)

func base() url.Values {
	v := url.Values{}
	v.Set("grant_type", GrantType)
	v.Set("subject_token", "subj-tok")
	v.Set("subject_token_type", TokenTypeAccessToken)
	return v
}

func TestParse_ImpersonationHappyPath(t *testing.T) {
	r, err := Parse(base())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.IsDelegation() {
		t.Fatal("no actor_token -> impersonation, IsDelegation must be false")
	}
	if r.SubjectToken != "subj-tok" || r.SubjectTokenType != TokenTypeAccessToken {
		t.Fatalf("unexpected request: %+v", r)
	}
}

func TestParse_DelegationHappyPath(t *testing.T) {
	v := base()
	v.Set("actor_token", "act-tok")
	v.Set("actor_token_type", TokenTypeJWT)
	v.Set("requested_token_type", TokenTypeAccessToken)
	v["audience"] = []string{"https://api.example.com"}
	v.Set("scope", "read write")

	r, err := Parse(v)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !r.IsDelegation() {
		t.Fatal("actor_token present -> delegation")
	}
	if len(r.Audience) != 1 || r.Audience[0] != "https://api.example.com" {
		t.Fatalf("audience not parsed: %+v", r.Audience)
	}
	if r.Scope != "read write" {
		t.Fatalf("scope = %q", r.Scope)
	}
}

func TestParse_WrongGrantType(t *testing.T) {
	v := base()
	v.Set("grant_type", "authorization_code")
	if _, err := Parse(v); !errors.Is(err, ErrWrongGrantType) {
		t.Fatalf("want ErrWrongGrantType, got %v", err)
	}
}

func TestParse_MissingSubjectToken(t *testing.T) {
	v := base()
	v.Del("subject_token")
	if _, err := Parse(v); !errors.Is(err, ErrMissingSubjectToken) {
		t.Fatalf("want ErrMissingSubjectToken, got %v", err)
	}
}

func TestParse_MissingSubjectTokenType(t *testing.T) {
	v := base()
	v.Del("subject_token_type")
	if _, err := Parse(v); !errors.Is(err, ErrMissingSubjectTokenType) {
		t.Fatalf("want ErrMissingSubjectTokenType, got %v", err)
	}
}

func TestParse_UnsupportedSubjectType(t *testing.T) {
	v := base()
	v.Set("subject_token_type", "urn:ietf:params:oauth:token-type:saml2")
	if _, err := Parse(v); !errors.Is(err, ErrUnsupportedSubjectType) {
		t.Fatalf("want ErrUnsupportedSubjectType, got %v", err)
	}
}

func TestParse_ActorTokenWithoutType(t *testing.T) {
	v := base()
	v.Set("actor_token", "act-tok")
	if _, err := Parse(v); !errors.Is(err, ErrMissingActorTokenType) {
		t.Fatalf("want ErrMissingActorTokenType, got %v", err)
	}
}

func TestParse_ActorTypeWithoutToken(t *testing.T) {
	v := base()
	v.Set("actor_token_type", TokenTypeJWT)
	if _, err := Parse(v); !errors.Is(err, ErrActorTokenTypeWithoutToken) {
		t.Fatalf("want ErrActorTokenTypeWithoutToken, got %v", err)
	}
}

func TestParse_UnsupportedActorType(t *testing.T) {
	v := base()
	v.Set("actor_token", "act-tok")
	v.Set("actor_token_type", "urn:ietf:params:oauth:token-type:saml2")
	if _, err := Parse(v); !errors.Is(err, ErrUnsupportedActorType) {
		t.Fatalf("want ErrUnsupportedActorType, got %v", err)
	}
}

func TestParse_UnsupportedRequestedType(t *testing.T) {
	v := base()
	v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:saml2")
	if _, err := Parse(v); !errors.Is(err, ErrUnsupportedRequestedType) {
		t.Fatalf("want ErrUnsupportedRequestedType, got %v", err)
	}
}

func TestParse_RequestedTypeOptional(t *testing.T) {
	// Absent requested_token_type is valid (server default applies).
	r, err := Parse(base())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.RequestedTokenType != "" {
		t.Fatalf("expected empty requested type, got %q", r.RequestedTokenType)
	}
}
