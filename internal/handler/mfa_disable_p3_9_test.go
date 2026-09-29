package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// P3-9: POST /api/profile/mfa/disable must re-verify the account (password +
// TOTP or recovery code) — a bearer token alone must not strip the second
// factor.

// p39UserService overrides only GetByID; the embedded nil interface makes any
// other call panic.
type p39UserService struct {
	service.UserService
	user *model.User
}

func (s *p39UserService) GetByID(_ context.Context, _ uint) (*model.User, error) {
	return s.user, nil
}

func p39Handler(t *testing.T, password string, verifyErr error, redeemOK bool) (*MFAHandler, *bool) {
	t.Helper()
	hash := ""
	if password != "" {
		var err error
		if hash, err = auth.HashPassword(password); err != nil {
			t.Fatalf("hash: %v", err)
		}
	}
	disabled := false
	h := NewMFAHandler(&mockMFAService{
		verifyFn:  func(_ context.Context, _ uint, _ string) error { return verifyErr },
		redeemFn:  func(_ context.Context, _ uint, _ string) (bool, error) { return redeemOK, nil },
		disableFn: func(_ context.Context, _ uint) error { disabled = true; return nil },
	}, &p39UserService{user: &model.User{ID: 7, HashedPassword: hash}})
	return h, &disabled
}

func p39Post(h *MFAHandler, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/disable",
		strings.NewReader(body)), 7)
	h.Disable(rr, req)
	return rr
}

func TestP39_Disable_BearerAloneIsNotEnough(t *testing.T) {
	h, disabled := p39Handler(t, "Correct-Horse-1!", nil, false)
	for _, body := range []string{``, `{}`, `{"password":"Correct-Horse-1!"}`} {
		rr := p39Post(h, body)
		if rr.Code == http.StatusNoContent || *disabled {
			t.Fatalf("body %q: MFA disabled without a code (status %d)", body, rr.Code)
		}
	}
}

func TestP39_Disable_WrongPassword_Rejected(t *testing.T) {
	h, disabled := p39Handler(t, "Correct-Horse-1!", nil, false)
	rr := p39Post(h, `{"password":"wrong","code":"123456"}`)
	if rr.Code != http.StatusUnauthorized || *disabled {
		t.Fatalf("status %d disabled=%v, want 401 and not disabled", rr.Code, *disabled)
	}
}

func TestP39_Disable_WrongCode_Rejected(t *testing.T) {
	h, disabled := p39Handler(t, "Correct-Horse-1!", service.ErrMFAInvalidCode, false)
	rr := p39Post(h, `{"password":"Correct-Horse-1!","code":"000000"}`)
	if rr.Code != http.StatusUnauthorized || *disabled {
		t.Fatalf("status %d disabled=%v, want 401 and not disabled", rr.Code, *disabled)
	}
}

func TestP39_Disable_PasswordAndTOTP_Succeeds(t *testing.T) {
	h, disabled := p39Handler(t, "Correct-Horse-1!", nil, false)
	rr := p39Post(h, `{"password":"Correct-Horse-1!","code":"123456"}`)
	if rr.Code != http.StatusNoContent || !*disabled {
		t.Fatalf("status %d disabled=%v, want 204 and disabled", rr.Code, *disabled)
	}
}

func TestP39_Disable_RecoveryCodeFallback(t *testing.T) {
	h, disabled := p39Handler(t, "Correct-Horse-1!", service.ErrMFAInvalidCode, true)
	rr := p39Post(h, `{"password":"Correct-Horse-1!","code":"aaaaa-bbbbb"}`)
	if rr.Code != http.StatusNoContent || !*disabled {
		t.Fatalf("status %d disabled=%v, want 204 via recovery code", rr.Code, *disabled)
	}
}

func TestP39_Disable_PasswordlessAccountStillNeedsCode(t *testing.T) {
	h, disabled := p39Handler(t, "", service.ErrMFAInvalidCode, false)
	if rr := p39Post(h, `{"code":"000000"}`); rr.Code != http.StatusUnauthorized || *disabled {
		t.Fatalf("status %d disabled=%v, want 401", rr.Code, *disabled)
	}
	h, disabled = p39Handler(t, "", nil, false)
	if rr := p39Post(h, `{"code":"123456"}`); rr.Code != http.StatusNoContent || !*disabled {
		t.Fatalf("status %d disabled=%v, want 204 for a valid code on a passwordless account", rr.Code, *disabled)
	}
}

func TestP39_Disable_NotEnrolled_409(t *testing.T) {
	h, _ := p39Handler(t, "Correct-Horse-1!", service.ErrMFANotEnrolled, false)
	if rr := p39Post(h, `{"password":"Correct-Horse-1!","code":"123456"}`); rr.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", rr.Code)
	}
}

func TestP39_Disable_NoUserService_FailsClosed(t *testing.T) {
	disabled := false
	h := NewMFAHandler(&mockMFAService{
		disableFn: func(_ context.Context, _ uint) error { disabled = true; return nil },
	}, nil)
	rr := p39Post(h, `{"password":"x","code":"123456"}`)
	if rr.Code == http.StatusNoContent || disabled {
		t.Fatalf("status %d disabled=%v: Disable must fail closed without a user service", rr.Code, disabled)
	}
}
