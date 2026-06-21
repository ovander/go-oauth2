package dto

// MFA (TOTP) self-service enrollment DTOs. See RFC-011 / EPIC-9.

// MFAEnrollResponse is returned by POST /api/profile/mfa/enroll. The secret and
// provisioning URI are exposed only once, at enrollment, so the user can add the
// account to an authenticator app; they are never re-served afterwards.
type MFAEnrollResponse struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

// MFAConfirmRequest is the body of POST /api/profile/mfa/confirm — the code the
// user reads from their authenticator app to prove enrollment.
type MFAConfirmRequest struct {
	Code string `json:"code"`
}

// MFAStatusResponse reports whether MFA is currently enabled for the user. It
// never includes the secret.
type MFAStatusResponse struct {
	Enabled bool `json:"enabled"`
}
