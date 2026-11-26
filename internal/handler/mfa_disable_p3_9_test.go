package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/service"
)

// P3-9: POST /api/profile/mfa/disable must re-verify the account (password +
// TOTP or recovery code) — a bearer token alone must not strip the second
// factor. The checks and the lockout are the auth service's
// (ReverifyForMFAChange, tested in internal/service); here, the handler hands
// it the password and code and answers by its verdict.

// fakeReverifier records what it was asked, and answers err.
type fakeReverifier struct {
	err      error
	calls    int
	password *string
	code     string
}

func (f *fakeReverifier) ReverifyForMFAChange(_ context.Context, userID uint, password *string, code string) error {
	f.calls++
	f.password, f.code = password, code
	if userID != 7 {
		return errors.New("wrong user")
	}
	return f.err
}

func p39Handler(err error) (*MFAHandler, *fakeReverifier, *bool) {
	disabled := false
	rv := &fakeReverifier{err: err}
	h := NewMFAHandler(&mockMFAService{
		disableFn: func(_ context.Context, _ uint) error { disabled = true; return nil },
	}, rv)
	return h, rv, &disabled
}

func p39Post(h *MFAHandler, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/disable",
		strings.NewReader(body)), 7)
	h.Disable(rr, req)
	return rr
}

func TestP39_Disable_BearerAloneIsNotEnough(t *testing.T) {
	h, rv, disabled := p39Handler(nil)
	for _, body := range []string{``, `{}`, `{"password":"Correct-Horse-1!"}`} {
		rr := p39Post(h, body)
		if rr.Code == http.StatusNoContent || *disabled {
			t.Fatalf("body %q: MFA disabled without a code (status %d)", body, rr.Code)
		}
	}
	if rv.calls != 0 {
		t.Errorf("the account was re-verified %d times without a code", rv.calls)
	}
}

func TestP39_Disable_PassesThePasswordAndCode(t *testing.T) {
	h, rv, disabled := p39Handler(nil)
	rr := p39Post(h, `{"password":"Correct-Horse-1!","code":"123456"}`)
	if rr.Code != http.StatusNoContent || !*disabled {
		t.Fatalf("status %d disabled=%v, want 204 and disabled", rr.Code, *disabled)
	}
	if rv.calls != 1 || rv.password == nil || *rv.password != "Correct-Horse-1!" || rv.code != "123456" {
		t.Errorf("re-verified with password %v, code %q (%d calls)", rv.password, rv.code, rv.calls)
	}
}

// Each refusal of the re-verification is answered without disabling MFA.
func TestP39_Disable_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"wrong password": {service.ErrInvalidCredentials, http.StatusUnauthorized},
		"wrong code":     {service.ErrMFAInvalidCode, http.StatusUnauthorized},
		"no code":        {service.ErrMFARequired, http.StatusUnauthorized},
		"locked":         {service.ErrAccountLocked, http.StatusForbidden},
		"not enrolled":   {service.ErrMFANotEnrolled, http.StatusConflict},
		"store error":    {errors.New("db down"), http.StatusInternalServerError},
	} {
		h, _, disabled := p39Handler(tc.err)
		rr := p39Post(h, `{"password":"x","code":"123456"}`)
		if rr.Code != tc.want || *disabled {
			t.Errorf("%s: status %d disabled=%v, want %d and not disabled", name, rr.Code, *disabled, tc.want)
		}
	}
}

func TestP39_Disable_NoReverifier_FailsClosed(t *testing.T) {
	disabled := false
	h := NewMFAHandler(&mockMFAService{
		disableFn: func(_ context.Context, _ uint) error { disabled = true; return nil },
	}, nil)
	rr := p39Post(h, `{"password":"x","code":"123456"}`)
	if rr.Code == http.StatusNoContent || disabled {
		t.Fatalf("status %d disabled=%v: Disable must fail closed without a re-verifier", rr.Code, disabled)
	}
}
