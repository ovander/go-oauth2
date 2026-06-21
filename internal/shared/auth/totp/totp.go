// Package totp implements TOTP (RFC 6238) on top of HOTP (RFC 4226) using only
// the standard library. It provides the primitives needed for multi-factor
// authentication — generating a shared secret, producing an authenticator
// provisioning URI, and validating a one-time code — with the de-facto
// authenticator defaults (HMAC-SHA1, 6 digits, 30-second period).
//
// HMAC-SHA1 is the correct, interoperable choice here: it is what Google
// Authenticator and compatible apps default to, and it is used as a keyed MAC,
// not for collision resistance.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// digits is the number of digits in a generated code.
	digits = 6
	// period is the time step, in seconds.
	period = 30
	// secretBytes is the size of a generated shared secret (160 bits, the
	// RFC 4226 recommended length for SHA1).
	secretBytes = 20
	// skewSteps is how many time steps before/after now are also accepted, to
	// tolerate clock drift between the server and the authenticator.
	skewSteps = 1
)

// b32 is unpadded, uppercase base32 — the encoding authenticator apps expect in
// otpauth secrets.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new random base32-encoded shared secret.
func GenerateSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return b32.EncodeToString(buf), nil
}

// ProvisioningURI returns an otpauth://totp URI for the given base32 secret,
// account label, and issuer, suitable for rendering as a QR code for an
// authenticator app. It encodes the algorithm/digits/period explicitly.
func ProvisioningURI(secret, account, issuer string) string {
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	q := url.Values{}
	q.Set("secret", secret)
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", digits))
	q.Set("period", fmt.Sprintf("%d", period))
	return "otpauth://totp/" + url.PathEscape(label) + "?" + q.Encode()
}

// ValidateCode reports whether code is a valid TOTP for secret at time t,
// accepting the current time step and ±skewSteps adjacent steps. The comparison
// is constant-time. An unparseable secret or a malformed code returns false.
func ValidateCode(secret, code string, t time.Time) bool {
	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false
	}
	counter := uint64(t.Unix()) / period
	for delta := -skewSteps; delta <= skewSteps; delta++ {
		c := counter
		if delta < 0 {
			c -= uint64(-delta)
		} else {
			c += uint64(delta)
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, c)), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// decodeSecret accepts the authenticator-standard unpadded base32, but also
// tolerates padded/whitespaced/lowercase input.
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	return b32.DecodeString(s)
}

// hotp computes the RFC 4226 HOTP value for key and counter, as a zero-padded
// `digits`-length decimal string.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}
