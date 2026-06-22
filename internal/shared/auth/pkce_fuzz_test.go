package auth

import "testing"

// FuzzVerifyPKCE asserts the PKCE verifier never panics and never accepts a
// mismatched S256 challenge or the downgrade-prone "plain" method (RFC 7636).
func FuzzVerifyPKCE(f *testing.F) {
	f.Add("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "challenge")
	f.Add("verifier", "")
	f.Add("", "challenge")
	f.Add("abc", "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0")

	f.Fuzz(func(t *testing.T, verifier, challenge string) {
		// S256: accept iff the challenge is exactly the verifier's hash.
		err := VerifyPKCE(verifier, challenge, "S256")
		if verifier != "" {
			want := GenerateCodeChallenge(verifier)
			if err == nil && challenge != want {
				t.Fatalf("S256 accepted a mismatched challenge: verifier=%q challenge=%q", verifier, challenge)
			}
			if err != nil && challenge == want {
				t.Fatalf("S256 rejected the correct challenge for verifier=%q", verifier)
			}
		}

		// "plain" is a downgrade and must always be rejected when PKCE is in use.
		if verifier != "" && challenge != "" {
			if VerifyPKCE(verifier, challenge, "plain") == nil {
				t.Fatalf("plain PKCE must be rejected (downgrade): verifier=%q", verifier)
			}
		}

		// An arbitrary/unknown method must not panic.
		_ = VerifyPKCE(verifier, challenge, "weird")
	})
}
