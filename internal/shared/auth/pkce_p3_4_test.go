package auth

import "testing"

// P3-4: a stored challenge with an empty method must never be verified as
// plain PKCE (verifier == challenge).
func TestP34_VerifyPKCE_EmptyMethodWithChallengeIsRejected(t *testing.T) {
	const v = "interceptable-verifier-equals-challenge"
	if err := VerifyPKCE(v, v, ""); err == nil {
		t.Fatal("VerifyPKCE accepted verifier == challenge with an empty method (plain PKCE by omission)")
	}
	// The genuine no-PKCE case is untouched.
	if err := VerifyPKCE("", "", ""); err != nil {
		t.Fatalf("no-PKCE case regressed: %v", err)
	}
}
