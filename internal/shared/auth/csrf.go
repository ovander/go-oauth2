// Package auth — CSRF protection helpers.
//
// CRIT-03 fix: implements the Double-Submit Cookie pattern (OWASP CSRF
// Prevention Cheat Sheet §Double Submit Cookie) for the /oauth/authorize
// login and consent forms.
//
// How it works:
//  1. On GET /oauth/authorize the server calls GenerateCSRFToken, which
//     places a 32-byte random value in a SameSite=Strict HttpOnly cookie
//     and returns the same value for embedding in the form as a hidden
//     field named "csrf_token".
//  2. On POST /oauth/authorize the server calls ValidateCSRFToken, which
//     reads the cookie and compares it (constant-time) to the form field.
//  3. A cross-origin attacker cannot forge a valid POST because:
//     - HttpOnly prevents XSS from reading the cookie via document.cookie.
//     - SameSite=Strict prevents the browser from attaching the cookie on
//     cross-site form submissions.
//     - Without the cookie value the attacker cannot supply a matching form
//     field, so validation fails.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

const (
	// CSRFCookieName is the name of the CSRF double-submit cookie.
	CSRFCookieName = "_csrf"
	// csrfCookieTTL is the cookie's Max-Age in seconds (10 minutes —
	// enough to fill in and submit the login/consent form).
	csrfCookieTTL = 600
)

// GenerateCSRFToken creates a cryptographically random 32-byte token, sets
// it as a SameSite=Strict HttpOnly cookie, and returns the token value.
// The caller must embed the returned value in the HTML form as a hidden
// <input type="hidden" name="csrf_token" value="...">.
//
// secure should be true when the server is serving over HTTPS (the Secure
// flag then instructs the browser not to send the cookie over plain HTTP).
func GenerateCSRFToken(w http.ResponseWriter, secure bool) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   csrfCookieTTL,
	})
	return token, nil
}

// ValidateCSRFToken returns true when the form-submitted csrf_token value
// matches the _csrf cookie value. The comparison is performed in constant
// time to prevent timing side-channels. Returns false when either value is
// absent or empty.
func ValidateCSRFToken(r *http.Request, formToken string) bool {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	if formToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) == 1
}
