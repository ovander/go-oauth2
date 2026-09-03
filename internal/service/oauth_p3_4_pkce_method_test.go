package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
)

// P3-4: an authorization request that carries a code_challenge must name S256
// explicitly. Omitting the method used to be stored as "" and verified as
// plain (verifier == challenge) at the token endpoint.

func p34Authorize(t *testing.T, method string) error {
	t.Helper()
	svc, _ := newHigh04Service(t, newMemUsedTokenRepo())
	svc.appRepo.(*crit02AppRepo).app.RedirectURIs = []string{"https://app.example/cb"}
	_, err := svc.Authorize(context.Background(), dto.AuthorizeRequest{
		ClientID: "test-client", RedirectURI: "https://app.example/cb",
		ResponseType: "code", Scope: "openid", State: "s",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: method,
		MaxAge:              -1,
	}, 42)
	return err
}

func TestP34_Authorize_RejectsOmittedAndPlainMethod(t *testing.T) {
	for _, method := range []string{"", "plain", "s256", "PLAIN"} {
		err := p34Authorize(t, method)
		if !errors.Is(err, ErrPKCEMethodUnsupported) {
			t.Errorf("method %q: err = %v, want ErrPKCEMethodUnsupported", method, err)
		}
	}
}

func TestP34_Authorize_AcceptsS256(t *testing.T) {
	if err := p34Authorize(t, "S256"); err != nil {
		t.Fatalf("S256 rejected: %v", err)
	}
}
