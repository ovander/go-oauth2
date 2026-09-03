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

// MFADisableRequest is the body of POST /api/profile/mfa/disable. Turning MFA
// off is a security-sensitive change, so the caller must re-prove possession
// of the account (P3-9): the current password (when the account has one) and
// a current TOTP code or an unused recovery code.
type MFADisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// MFAStatusResponse reports whether MFA is currently enabled for the user and
// how many recovery codes remain (so a client can prompt to regenerate before
// they run out). It never includes the secret.
type MFAStatusResponse struct {
	Enabled                bool `json:"enabled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
}

// MFARecoveryCodesResponse carries a freshly generated set of one-time backup
// codes. They are shown only once (stored hashed) — the user must save them.
type MFARecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}
