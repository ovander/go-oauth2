package auth

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

var consentSecret = []byte("consent-authn-test-secret-32-bytes!!")

// The sign-in evidence rides in the signed consent payload: it round-trips,
// cannot be altered, and a token without it reads as the zero value.
func TestConsentToken_CarriesAuthnEvidence(t *testing.T) {
	ev := AuthnEvidence{AuthTime: 1791000000, AMR: []string{"pwd", "otp", "mfa"}, ACR: "mfa"}
	tok, err := IssueConsentTokenWithAuthn(42, "client-a", ev, consentSecret)
	if err != nil {
		t.Fatal(err)
	}
	uid, cid, got, err := ValidateConsentTokenWithAuthn(tok, consentSecret)
	if err != nil || uid != 42 || cid != "client-a" || !reflect.DeepEqual(got, ev) {
		t.Fatalf("round trip = %d %q %+v %v", uid, cid, got, err)
	}

	// Swapping in another payload (e.g. a fresher auth_time) breaks the MAC.
	other, _ := IssueConsentTokenWithAuthn(42, "client-a", AuthnEvidence{AuthTime: 1791009999}, []byte("another-secret-of-32-bytes-length!"))
	forged := strings.SplitN(other, ".", 2)[0] + "." + strings.SplitN(tok, ".", 2)[1]
	if _, _, _, err := ValidateConsentTokenWithAuthn(forged, consentSecret); !errors.Is(err, ErrConsentTokenInvalid) {
		t.Fatalf("altered evidence accepted: %v", err)
	}

	// The historical token (no evidence) still validates, with zero evidence.
	plain, _ := IssueConsentToken(7, "client-b", consentSecret)
	if uid, _, got, err := ValidateConsentTokenWithAuthn(plain, consentSecret); err != nil || uid != 7 || !reflect.DeepEqual(got, AuthnEvidence{}) {
		t.Fatalf("plain token = %d %+v %v", uid, got, err)
	}
	if uid, cid, err := ValidateConsentToken(tok, consentSecret); err != nil || uid != 42 || cid != "client-a" {
		t.Fatalf("ValidateConsentToken on an evidence token = %d %q %v", uid, cid, err)
	}
}
