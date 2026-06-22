package service

import "testing"

func TestLoginAuthnContext(t *testing.T) {
	// Password-only login.
	amr, acr := loginAuthnContext(false)
	if acr != "pwd" || len(amr) != 1 || amr[0] != "pwd" {
		t.Fatalf("single-factor: amr/acr = %v / %q, want [pwd] / pwd", amr, acr)
	}

	// Password + MFA login.
	amr, acr = loginAuthnContext(true)
	if acr != "mfa" || len(amr) != 3 || amr[0] != "pwd" || amr[1] != "otp" || amr[2] != "mfa" {
		t.Fatalf("multi-factor: amr/acr = %v / %q, want [pwd otp mfa] / mfa", amr, acr)
	}
}
