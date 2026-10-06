package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

var accountSecret = []byte("account-page-test-secret-at-least-32-bytes")

// accountAuth answers AuthenticateAccount; the embedded nil interface makes any
// other call fail loudly.
type accountAuth struct {
	service.AuthService
	user *model.User
	err  error
}

func (a *accountAuth) AuthenticateAccount(context.Context, string, string, string) (*model.User, error) {
	return a.user, a.err
}

// accountMFA is an in-memory MFA service for one user.
type accountMFA struct {
	enabled   bool
	pending   bool
	validCode string
	recovery  map[string]bool
	disabled  bool
}

func (m *accountMFA) BeginEnrollment(context.Context, uint) (string, string, error) {
	if m.enabled {
		return "", "", service.ErrMFAAlreadyEnabled
	}
	m.pending = true
	return "JBSWY3DPEHPK3PXP", "otpauth://totp/Socrate:op@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Socrate", nil
}
func (m *accountMFA) ConfirmEnrollment(_ context.Context, _ uint, code string) error {
	if !m.pending {
		return service.ErrMFANotEnrolled
	}
	if code != m.validCode {
		return service.ErrMFAInvalidCode
	}
	m.enabled, m.pending = true, false
	return nil
}
func (m *accountMFA) Verify(_ context.Context, _ uint, code string) error {
	if !m.enabled {
		return service.ErrMFANotEnrolled
	}
	if code != m.validCode {
		return service.ErrMFAInvalidCode
	}
	return nil
}
func (m *accountMFA) Disable(context.Context, uint) error {
	m.enabled, m.disabled = false, true
	return nil
}
func (m *accountMFA) IsEnabled(context.Context, uint) (bool, error) { return m.enabled, nil }
func (m *accountMFA) GenerateRecoveryCodes(context.Context, uint) ([]string, error) {
	if !m.enabled {
		return nil, service.ErrMFANotEnrolled
	}
	m.recovery = map[string]bool{"aaaa-bbbb": true, "cccc-dddd": true}
	return []string{"aaaa-bbbb", "cccc-dddd"}, nil
}
func (m *accountMFA) RedeemRecoveryCode(_ context.Context, _ uint, code string) (bool, error) {
	if m.recovery[code] {
		delete(m.recovery, code)
		return true, nil
	}
	return false, nil
}
func (m *accountMFA) RemainingRecoveryCodes(context.Context, uint) (int, error) {
	return len(m.recovery), nil
}

func newAccountHandler(t *testing.T, a service.AuthService, m service.MFAService) *AccountSecurityHandler {
	t.Helper()
	h, err := NewAccountSecurityHandler(a, m, accountSecret, "https://auth.example")
	if err != nil {
		t.Fatalf("NewAccountSecurityHandler: %v", err)
	}
	return h
}

var (
	csrfField    = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	sessionField = regexp.MustCompile(`name="session" value="([^"]+)"`)
)

// page is one rendered response, with the CSRF cookie it set.
type page struct {
	body   string
	header http.Header
	cookie *http.Cookie
}

func (p page) csrf(t *testing.T) string {
	t.Helper()
	m := csrfField.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no csrf_token in page:\n%s", p.body)
	}
	return m[1]
}

func (p page) session() string {
	if m := sessionField.FindStringSubmatch(p.body); m != nil {
		return m[1]
	}
	return ""
}

func get(t *testing.T, h *AccountSecurityHandler) page {
	t.Helper()
	rr := httptest.NewRecorder()
	h.Page(rr, httptest.NewRequest(http.MethodGet, "/account/security", nil))
	return toPage(t, rr)
}

// post submits a form from prev: its CSRF cookie and token, plus fields.
func post(t *testing.T, h *AccountSecurityHandler, prev page, fields url.Values) page {
	t.Helper()
	if fields.Get("csrf_token") == "" {
		fields.Set("csrf_token", prev.csrf(t))
	}
	req := httptest.NewRequest(http.MethodPost, "/account/security", strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if prev.cookie != nil {
		req.AddCookie(prev.cookie)
	}
	rr := httptest.NewRecorder()
	h.Submit(rr, req)
	return toPage(t, rr)
}

func toPage(t *testing.T, rr *httptest.ResponseRecorder) page {
	t.Helper()
	p := page{body: rr.Body.String(), header: rr.Header()}
	for _, c := range rr.Result().Cookies() {
		if c.Name == auth.CSRFCookieName {
			p.cookie = c
		}
	}
	return p
}

func signIn(t *testing.T, h *AccountSecurityHandler) page {
	t.Helper()
	p := post(t, h, get(t, h), url.Values{"action": {"signin"}, "email": {"op@example.com"}, "password": {"pw"}})
	if p.session() == "" {
		t.Fatalf("no page session after sign-in:\n%s", p.body)
	}
	return p
}

func TestAccountPage_EnrolFromSignInToRecoveryCodes(t *testing.T) {
	mfa := &accountMFA{validCode: "123456"}
	h := newAccountHandler(t, &accountAuth{user: &model.User{ID: 7}}, mfa)

	first := get(t, h)
	if !strings.Contains(first.body, `name="password"`) || first.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET should show the sign-in form, no-store; got %q\n%s", first.header.Get("Cache-Control"), first.body)
	}

	overview := signIn(t, h)
	if !strings.Contains(overview.body, "Two-factor authentication is off") {
		t.Fatalf("overview should say MFA is off:\n%s", overview.body)
	}

	enroll := post(t, h, overview, url.Values{"action": {"enroll"}, "session": {overview.session()}})
	if !strings.Contains(enroll.body, "JBSW Y3DP EHPK 3PXP") {
		t.Errorf("the key should be shown in groups of four:\n%s", enroll.body)
	}
	if !strings.Contains(enroll.body, `href="otpauth://totp/Socrate:op@example.com?secret=JBSWY3DPEHPK3PXP&amp;issuer=Socrate"`) {
		t.Errorf("the otpauth link should be kept (not #ZgotmplZ):\n%s", enroll.body)
	}

	bad := post(t, h, enroll, url.Values{"action": {"confirm"}, "session": {enroll.session()}, "code": {"000000"}})
	if !strings.Contains(bad.body, "Code not accepted") || mfa.enabled {
		t.Fatalf("a wrong code must not turn MFA on:\n%s", bad.body)
	}

	codes := post(t, h, bad, url.Values{"action": {"confirm"}, "session": {bad.session()}, "code": {"123456"}})
	if !mfa.enabled || !strings.Contains(codes.body, "aaaa-bbbb") || !strings.Contains(codes.body, "cccc-dddd") {
		t.Fatalf("confirming should turn MFA on and show the recovery codes:\n%s", codes.body)
	}
	if codes.header.Get("Cache-Control") != "no-store" || codes.header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("recovery codes must not be cached or leak a referrer: %v", codes.header)
	}

	done := post(t, h, codes, url.Values{"action": {"overview"}, "session": {codes.session()}})
	if !strings.Contains(done.body, "Two-factor authentication is on") || !strings.Contains(done.body, "2 recovery code(s) left") {
		t.Errorf("overview should say MFA is on with 2 codes:\n%s", done.body)
	}
}

func TestAccountPage_DisableNeedsAFreshCode(t *testing.T) {
	mfa := &accountMFA{enabled: true, validCode: "123456", recovery: map[string]bool{"rc-1": true}}
	h := newAccountHandler(t, &accountAuth{user: &model.User{ID: 7}}, mfa)
	p := signIn(t, h)

	p = post(t, h, p, url.Values{"action": {"disable"}, "session": {p.session()}, "code": {"999999"}})
	if mfa.disabled || !strings.Contains(p.body, "Code not accepted") {
		t.Fatalf("a wrong code must not turn MFA off:\n%s", p.body)
	}
	p = post(t, h, p, url.Values{"action": {"disable"}, "session": {p.session()}, "code": {"rc-1"}})
	if !mfa.disabled || !strings.Contains(p.body, "Two-factor authentication is off") {
		t.Fatalf("a recovery code should turn MFA off:\n%s", p.body)
	}
}

func TestAccountPage_RefusesWithoutCSRF(t *testing.T) {
	mfa := &accountMFA{}
	h := newAccountHandler(t, &accountAuth{user: &model.User{ID: 7}}, mfa)
	p := signIn(t, h)

	// The right session but no CSRF cookie (a cross-site post).
	req := httptest.NewRequest(http.MethodPost, "/account/security", strings.NewReader(url.Values{
		"action": {"enroll"}, "session": {p.session()}, "csrf_token": {p.csrf(t)},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Submit(rr, req)
	if mfa.pending || !strings.Contains(rr.Body.String(), "This page expired") {
		t.Fatalf("a post without the CSRF cookie must be refused:\n%s", rr.Body.String())
	}
}

func TestAccountPage_RefusesABadSession(t *testing.T) {
	mfa := &accountMFA{}
	h := newAccountHandler(t, &accountAuth{user: &model.User{ID: 7}}, mfa)
	start := get(t, h)

	// A consent token for an OAuth client is not a page session.
	consent, err := auth.IssueConsentToken(7, "some-client", accountSecret)
	if err != nil {
		t.Fatal(err)
	}
	for name, session := range map[string]string{"none": "", "forged": "eyJ1aWQiOjd9.c2ln", "consent token": consent} {
		p := post(t, h, start, url.Values{"action": {"enroll"}, "session": {session}})
		if mfa.pending || !strings.Contains(p.body, "Your session ended") {
			t.Errorf("%s: must be refused:\n%s", name, p.body)
		}
	}
}

func TestAccountPage_SignInErrors(t *testing.T) {
	cases := []struct {
		err     error
		message string
		mfa     bool
	}{
		{service.ErrInvalidCredentials, "Invalid email, password or authentication code", false},
		{service.ErrMFARequired, "code from your authenticator app", true},
		{service.ErrMFAInvalidCode, "Invalid email, password or authentication code", true},
		{service.ErrAccountLocked, "locked", false},
		{service.ErrAccountPageAdmin, "admin console", false},
	}
	for _, c := range cases {
		h := newAccountHandler(t, &accountAuth{err: c.err}, &accountMFA{})
		p := post(t, h, get(t, h), url.Values{"action": {"signin"}, "email": {"op@example.com"}, "password": {"pw"}})
		if !strings.Contains(p.body, c.message) || p.session() != "" {
			t.Errorf("%v: want %q and no session:\n%s", c.err, c.message, p.body)
		}
		if got := strings.Contains(p.body, `name="mfa_code"`); got != c.mfa {
			t.Errorf("%v: code field shown = %v, want %v", c.err, got, c.mfa)
		}
	}
}

func TestNewAccountSecurityHandler_RequiresASecret(t *testing.T) {
	if _, err := NewAccountSecurityHandler(&accountAuth{}, &accountMFA{}, nil, "https://auth.example"); err == nil {
		t.Error("an empty SECRET_KEY_BASE must be refused")
	}
}
