// Package auth — tests for CRIT-04: signed consent token (stateless user identity).
//
// CRIT-04 fix: after successful login the handler renders a consent page
// instead of immediately issuing an authorization code.  The consent page
// carries the user's identity in an HMAC-signed token so the consent POST
// can authenticate the user without a server-side session.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

var testSecret = []byte("test-secret-key-that-is-32-bytes!!")

// issueConsentTokenAt is a test helper that builds a consent token with a
// specific expiry time so that expiry tests do not need to sleep.
func issueConsentTokenAt(userID uint, clientID string, secret []byte, exp time.Time) (string, error) {
	payload := consentPayload{
		UserID:   userID,
		ClientID: clientID,
		Exp:      exp.Unix(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payloadB64 + "." + sig, nil
}

// ---------------------------------------------------------------------------
// IssueConsentToken
// ---------------------------------------------------------------------------

func TestIssueConsentToken_EmptySecret_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := IssueConsentToken(42, "client-abc", nil)
	if err == nil {
		t.Fatal("expected error for empty secret, got nil")
	}
}

func TestIssueConsentToken_ValidInputs_ReturnsNonEmptyToken(t *testing.T) {
	t.Parallel()
	token, err := IssueConsentToken(42, "client-abc", testSecret)
	if err != nil {
		t.Fatalf("IssueConsentToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("IssueConsentToken() returned empty token")
	}
}

func TestIssueConsentToken_TokenContainsDot(t *testing.T) {
	// The token format is <base64url payload>.<base64url signature>.
	t.Parallel()
	token, _ := IssueConsentToken(1, "c", testSecret)
	hasDot := false
	for _, ch := range token {
		if ch == '.' {
			hasDot = true
			break
		}
	}
	if !hasDot {
		t.Errorf("consent token %q has no dot separator", token)
	}
}

// ---------------------------------------------------------------------------
// ValidateConsentToken — happy path
// ---------------------------------------------------------------------------

func TestValidateConsentToken_RoundTrip_ReturnsCorrectValues(t *testing.T) {
	t.Parallel()
	wantUserID := uint(99)
	wantClientID := "my-app"

	token, err := IssueConsentToken(wantUserID, wantClientID, testSecret)
	if err != nil {
		t.Fatalf("IssueConsentToken: %v", err)
	}

	gotUserID, gotClientID, err := ValidateConsentToken(token, testSecret)
	if err != nil {
		t.Fatalf("ValidateConsentToken() error = %v", err)
	}
	if gotUserID != wantUserID {
		t.Errorf("userID = %d, want %d", gotUserID, wantUserID)
	}
	if gotClientID != wantClientID {
		t.Errorf("clientID = %q, want %q", gotClientID, wantClientID)
	}
}

// ---------------------------------------------------------------------------
// ValidateConsentToken — error cases
// ---------------------------------------------------------------------------

func TestValidateConsentToken_EmptySecret_ReturnsError(t *testing.T) {
	t.Parallel()
	token, _ := IssueConsentToken(1, "c", testSecret)
	_, _, err := ValidateConsentToken(token, nil)
	if err == nil {
		t.Fatal("expected error for empty secret, got nil")
	}
}

func TestValidateConsentToken_EmptyToken_ReturnsInvalid(t *testing.T) {
	t.Parallel()
	_, _, err := ValidateConsentToken("", testSecret)
	if err != ErrConsentTokenInvalid {
		t.Errorf("error = %v, want ErrConsentTokenInvalid", err)
	}
}

func TestValidateConsentToken_NoDotSeparator_ReturnsInvalid(t *testing.T) {
	t.Parallel()
	_, _, err := ValidateConsentToken("nodot", testSecret)
	if err != ErrConsentTokenInvalid {
		t.Errorf("error = %v, want ErrConsentTokenInvalid", err)
	}
}

func TestValidateConsentToken_TamperedPayload_ReturnsInvalid(t *testing.T) {
	t.Parallel()
	token, _ := IssueConsentToken(1, "c", testSecret)
	// Corrupt the payload section (replace the first four chars).
	tampered := "XXXX" + token[4:]
	_, _, err := ValidateConsentToken(tampered, testSecret)
	if err != ErrConsentTokenInvalid {
		t.Errorf("tampered payload: error = %v, want ErrConsentTokenInvalid", err)
	}
}

func TestValidateConsentToken_TamperedSignature_ReturnsInvalid(t *testing.T) {
	t.Parallel()
	token, _ := IssueConsentToken(1, "c", testSecret)
	// Find the dot and corrupt only the signature part.
	for i, ch := range token {
		if ch == '.' {
			tampered := token[:i+1] + "XXXX"
			_, _, err := ValidateConsentToken(tampered, testSecret)
			if err != ErrConsentTokenInvalid {
				t.Errorf("tampered sig: error = %v, want ErrConsentTokenInvalid", err)
			}
			return
		}
	}
	t.Fatal("no dot found in generated token")
}

func TestValidateConsentToken_WrongSecret_ReturnsInvalid(t *testing.T) {
	t.Parallel()
	token, _ := IssueConsentToken(1, "c", testSecret)
	_, _, err := ValidateConsentToken(token, []byte("different-secret-key-32-bytes!!!"))
	if err != ErrConsentTokenInvalid {
		t.Errorf("wrong secret: error = %v, want ErrConsentTokenInvalid", err)
	}
}

func TestValidateConsentToken_ExpiredToken_ReturnsExpired(t *testing.T) {
	t.Parallel()
	// Use the test helper to build a token with exp already in the past.
	token, err := issueConsentTokenAt(1, "c", testSecret, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("issueConsentTokenAt: %v", err)
	}
	_, _, err = ValidateConsentToken(token, testSecret)
	if err != ErrConsentTokenExpired {
		t.Errorf("expired token: error = %v, want ErrConsentTokenExpired", err)
	}
}

func TestValidateConsentToken_FutureExpiry_IsValid(t *testing.T) {
	t.Parallel()
	token, err := issueConsentTokenAt(7, "app-x", testSecret, time.Now().Add(consentTokenTTL))
	if err != nil {
		t.Fatalf("issueConsentTokenAt: %v", err)
	}
	gotUID, gotCID, err := ValidateConsentToken(token, testSecret)
	if err != nil {
		t.Fatalf("ValidateConsentToken() error = %v", err)
	}
	if gotUID != 7 {
		t.Errorf("userID = %d, want 7", gotUID)
	}
	if gotCID != "app-x" {
		t.Errorf("clientID = %q, want app-x", gotCID)
	}
}
