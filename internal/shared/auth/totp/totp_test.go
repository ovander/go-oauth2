package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B test seed (ASCII), base32-encoded as authenticators expect.
var rfcSeed = b32.EncodeToString([]byte("12345678901234567890"))

// RFC 6238 SHA1 vectors: timestamp → 8-digit TOTP; we assert the 6-digit form
// (the last 6 digits).
func TestValidateCode_RFC6238Vectors(t *testing.T) {
	t.Parallel()
	vectors := []struct {
		unix int64
		code string // last 6 digits of the RFC's 8-digit value
	}{
		{59, "287082"},         // 94287082
		{1111111109, "081804"}, // 07081804
		{1111111111, "050471"}, // 14050471
		{1234567890, "005924"}, // 89005924
		{2000000000, "279037"}, // 69279037
	}
	for _, v := range vectors {
		at := time.Unix(v.unix, 0)
		if !ValidateCode(rfcSeed, v.code, at) {
			t.Errorf("ValidateCode(seed, %s, T=%d) = false, want true", v.code, v.unix)
		}
		if ValidateCode(rfcSeed, "000000", at) {
			t.Errorf("ValidateCode(seed, 000000, T=%d) = true, want false", v.unix)
		}
	}
}

func TestValidateCode_ClockSkewWindow(t *testing.T) {
	t.Parallel()
	code := "287082" // valid for step floor(59/30)=1
	base := int64(59)

	// Within ±1 step (±30s): accepted.
	for _, off := range []int64{-30, 0, 30} {
		if !ValidateCode(rfcSeed, code, time.Unix(base+off, 0)) {
			t.Errorf("expected code accepted at offset %ds", off)
		}
	}
	// Beyond the window (+90s ⇒ steps 3,4,5): rejected.
	if ValidateCode(rfcSeed, code, time.Unix(base+90, 0)) {
		t.Error("expected code rejected outside the ±1 step window")
	}
}

func TestValidateCode_MalformedInputs(t *testing.T) {
	t.Parallel()
	now := time.Unix(59, 0)
	cases := []struct{ secret, code string }{
		{rfcSeed, "12345"},          // too short
		{rfcSeed, "1234567"},        // too long
		{"not base32 !!", "287082"}, // bad secret
	}
	for _, c := range cases {
		if ValidateCode(c.secret, c.code, now) {
			t.Errorf("ValidateCode(%q, %q) = true, want false", c.secret, c.code)
		}
	}
}

func TestGenerateSecret_RoundTrip(t *testing.T) {
	t.Parallel()
	s1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	s2, _ := GenerateSecret()
	if s1 == s2 {
		t.Error("two generated secrets are identical")
	}
	if _, err := decodeSecret(s1); err != nil {
		t.Errorf("generated secret is not valid base32: %v", err)
	}

	// A code computed from the secret validates against it.
	now := time.Now()
	key, _ := decodeSecret(s1)
	code := hotp(key, uint64(now.Unix())/period)
	if !ValidateCode(s1, code, now) {
		t.Error("freshly generated code should validate against its secret")
	}
}

func TestProvisioningURI_WellFormed(t *testing.T) {
	t.Parallel()
	uri := ProvisioningURI("ABCDEFGHIJKLMNOP", "alice@example.com", "Socrate")
	for _, want := range []string{
		"otpauth://totp/",
		"secret=ABCDEFGHIJKLMNOP",
		"issuer=Socrate",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("provisioning URI %q missing %q", uri, want)
		}
	}
}
