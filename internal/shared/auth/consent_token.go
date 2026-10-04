// Package auth — short-lived signed consent tokens.
//
// CRIT-04 fix: the consent screen must carry the authenticated user's
// identity from the GET /oauth/authorize response (where the identity was
// established) to the POST /oauth/authorize consent submission (a fresh
// HTTP request with no auth session).
//
// We use a stateless HMAC-SHA256-signed token so that no server-side
// session is needed:
//
//	token = base64url(JSON payload) "." base64url(HMAC-SHA256(payload, secret))
//
// The payload contains the userID, clientID, and an expiry timestamp.
// Validation verifies the signature, checks expiry, and returns the
// embedded identifiers.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const consentTokenTTL = 10 * time.Minute

// ErrConsentTokenInvalid is returned when the token has an invalid
// signature, a malformed payload, or an empty secret is supplied.
var ErrConsentTokenInvalid = errors.New("invalid consent token")

// ErrConsentTokenExpired is returned when a well-formed token's expiry
// time has passed.
var ErrConsentTokenExpired = errors.New("consent token expired")

// consentPayload is the JSON body embedded inside a consent token.
type consentPayload struct {
	UserID   uint   `json:"uid"`
	ClientID string `json:"cid"`
	Exp      int64  `json:"exp"`
	// Authn is how and when the user authenticated before this consent page.
	// It rides in the signed payload so the authorization code (and every
	// token minted from it) carries the real sign-in evidence. Absent in
	// tokens issued before it existed: the zero value.
	Authn *AuthnEvidence `json:"authn,omitempty"`
}

// AuthnEvidence is the end-user authentication behind a grant: when it
// happened (auth_time, Unix seconds; zero when unknown) and how (RFC 8176 amr
// and acr). It travels from the sign-in, through the consent token and the
// authorization code, into the access, ID and refresh tokens.
type AuthnEvidence struct {
	AuthTime int64    `json:"at,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	ACR      string   `json:"acr,omitempty"`
}

// IssueConsentToken returns a short-lived HMAC-signed token that binds
// userID and clientID together.  It is embedded as a hidden form field
// in the consent page and validated on the consent POST to identify the
// consenting user without a server-side session.
//
// secret must be non-empty; ErrConsentTokenInvalid is returned when it
// is empty so that callers cannot accidentally issue unverifiable tokens
// (e.g. in environments where SecretKeyBase is not configured).
func IssueConsentToken(userID uint, clientID string, secret []byte) (string, error) {
	return IssueConsentTokenWithAuthn(userID, clientID, AuthnEvidence{}, secret)
}

// IssueConsentTokenWithAuthn is IssueConsentToken carrying the authentication
// evidence of the sign-in that precedes the consent page, signed with the rest
// of the payload so it cannot be altered by the browser.
func IssueConsentTokenWithAuthn(userID uint, clientID string, authn AuthnEvidence, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", ErrConsentTokenInvalid
	}

	payload := consentPayload{
		UserID:   userID,
		ClientID: clientID,
		Exp:      time.Now().Add(consentTokenTTL).Unix(),
	}
	if authn.AuthTime != 0 || len(authn.AMR) > 0 || authn.ACR != "" {
		payload.Authn = &authn
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

// ValidateConsentToken verifies a consent token and returns the embedded
// userID and clientID.  Returns ErrConsentTokenInvalid if the signature
// does not match or the token is malformed, and ErrConsentTokenExpired if
// the token's expiry time has passed.
//
// The HMAC comparison uses hmac.Equal (constant-time) to prevent timing
// side-channels.
func ValidateConsentToken(token string, secret []byte) (userID uint, clientID string, err error) {
	userID, clientID, _, err = ValidateConsentTokenWithAuthn(token, secret)
	return userID, clientID, err
}

// ValidateConsentTokenWithAuthn is ValidateConsentToken that also returns the
// signed authentication evidence (the zero value when the token carries none).
func ValidateConsentTokenWithAuthn(token string, secret []byte) (userID uint, clientID string, authn AuthnEvidence, err error) {
	if len(secret) == 0 {
		return 0, "", AuthnEvidence{}, ErrConsentTokenInvalid
	}

	dot := strings.IndexByte(token, '.')
	if dot < 0 {
		return 0, "", AuthnEvidence{}, ErrConsentTokenInvalid
	}

	payloadB64 := token[:dot]
	sigB64 := token[dot+1:]

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Constant-time comparison prevents timing attacks.
	if !hmac.Equal([]byte(sigB64), []byte(expectedSig)) {
		return 0, "", AuthnEvidence{}, ErrConsentTokenInvalid
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return 0, "", AuthnEvidence{}, ErrConsentTokenInvalid
	}

	var p consentPayload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return 0, "", AuthnEvidence{}, ErrConsentTokenInvalid
	}

	if time.Now().Unix() > p.Exp {
		return 0, "", AuthnEvidence{}, ErrConsentTokenExpired
	}

	if p.Authn != nil {
		authn = *p.Authn
	}
	return p.UserID, p.ClientID, authn, nil
}
