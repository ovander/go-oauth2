package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
)

// MFA_RECOVERY_CODES_REVERIFY_MODE: new recovery codes are a second factor, so
// under enforce a bearer token alone does not replace them; the caller
// re-proves the account as for disable (the checks and the lockout are the
// auth service's ReverifyForMFAChange). Observe only audits whether the
// request carried a password and a code; off changes nothing.

func recoveryHandler(mode string, rvErr error) (*MFAHandler, *fakeReverifier, *captureAuditService, *int) {
	generated := 0
	rv := &fakeReverifier{err: rvErr}
	h := NewMFAHandler(&mockMFAService{
		recoveryFn: func(_ context.Context, _ uint) ([]string, error) {
			generated++
			return []string{"aaaa-bbbb"}, nil
		},
	}, rv)
	audit := &captureAuditService{}
	h.SetRecoveryCodesReverify(mode, audit)
	return h, rv, audit, &generated
}

func recoveryPost(h *MFAHandler, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.RecoveryCodes(rr, withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/recovery-codes",
		strings.NewReader(body)), 7))
	return rr
}

func lastOutcome(t *testing.T, a *captureAuditService) (string, bool) {
	t.Helper()
	if len(a.events) == 0 {
		t.Fatal("nothing audited")
	}
	e := a.events[len(a.events)-1]
	if e.EventType != model.SecurityEventMFARecoveryCodesReverify || e.UserID == nil || *e.UserID != 7 {
		t.Fatalf("audited %+v, want %s for user 7", e, model.SecurityEventMFARecoveryCodesReverify)
	}
	outcome, _ := e.Details["outcome"].(string)
	return outcome, e.Success
}

func TestRecoveryCodesReverify_OffIsUnchanged(t *testing.T) {
	for _, mode := range []string{"", "off", "bogus"} {
		h, rv, audit, generated := recoveryHandler(mode, nil)
		if rr := recoveryPost(h, ``); rr.Code != http.StatusOK || *generated != 1 {
			t.Fatalf("mode %q: status %d, generated %d, want 200 and 1", mode, rr.Code, *generated)
		}
		if rv.calls != 0 || len(audit.events) != 0 {
			t.Errorf("mode %q: re-verified %d times, audited %d events, want none", mode, rv.calls, len(audit.events))
		}
	}
}

func TestRecoveryCodesReverify_ObserveAuditsAndServes(t *testing.T) {
	for _, tc := range []struct{ body, outcome string }{
		{``, "would_refuse_missing"},
		{`{}`, "would_refuse_missing"},
		{`not json`, "would_refuse_missing"},
		{`{"password":"Correct-Horse-1!","code":"123456"}`, "credentials_present"},
	} {
		h, rv, audit, generated := recoveryHandler("observe", nil)
		if rr := recoveryPost(h, tc.body); rr.Code != http.StatusOK || *generated != 1 {
			t.Fatalf("body %q: status %d, generated %d, want 200 and 1", tc.body, rr.Code, *generated)
		}
		if rv.calls != 0 {
			t.Errorf("body %q: observe checked the credentials (%d calls)", tc.body, rv.calls)
		}
		if outcome, ok := lastOutcome(t, audit); outcome != tc.outcome || !ok {
			t.Errorf("body %q: audited %q success=%v, want %q success=true", tc.body, outcome, ok, tc.outcome)
		}
	}
}

func TestRecoveryCodesReverify_EnforceNeedsACode(t *testing.T) {
	for _, body := range []string{``, `{}`, `not json`, `{"password":"Correct-Horse-1!"}`} {
		h, rv, audit, generated := recoveryHandler("enforce", nil)
		if rr := recoveryPost(h, body); rr.Code != http.StatusBadRequest || *generated != 0 {
			t.Fatalf("body %q: status %d, generated %d, want 400 and none", body, rr.Code, *generated)
		}
		if rv.calls != 0 {
			t.Errorf("body %q: re-verified without a code", body)
		}
		if outcome, ok := lastOutcome(t, audit); outcome != "refused_missing" || ok {
			t.Errorf("body %q: audited %q success=%v, want refused_missing success=false", body, outcome, ok)
		}
	}
}

func TestRecoveryCodesReverify_EnforceRefusals(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{service.ErrMFAInvalidCode, http.StatusUnauthorized},
		{service.ErrInvalidCredentials, http.StatusUnauthorized},
		{service.ErrAccountLocked, http.StatusForbidden},
		{service.ErrMFANotEnrolled, http.StatusConflict},
	} {
		h, _, audit, generated := recoveryHandler("enforce", tc.err)
		if rr := recoveryPost(h, `{"password":"x","code":"000000"}`); rr.Code != tc.want || *generated != 0 {
			t.Fatalf("%v: status %d, generated %d, want %d and none", tc.err, rr.Code, *generated, tc.want)
		}
		if outcome, ok := lastOutcome(t, audit); outcome != "refused_failed" || ok {
			t.Errorf("%v: audited %q success=%v, want refused_failed success=false", tc.err, outcome, ok)
		}
	}
}

func TestRecoveryCodesReverify_EnforceVerified(t *testing.T) {
	h, rv, audit, generated := recoveryHandler("enforce", nil)
	rr := recoveryPost(h, `{"password":"Correct-Horse-1!","code":"123456"}`)
	if rr.Code != http.StatusOK || *generated != 1 || !strings.Contains(rr.Body.String(), "aaaa-bbbb") {
		t.Fatalf("status %d, generated %d, body %s; want 200 with the codes", rr.Code, *generated, rr.Body.String())
	}
	if rv.calls != 1 || rv.password == nil || *rv.password != "Correct-Horse-1!" || rv.code != "123456" {
		t.Errorf("re-verified %d times with code %q", rv.calls, rv.code)
	}
	if outcome, ok := lastOutcome(t, audit); outcome != "verified" || !ok {
		t.Errorf("audited %q success=%v, want verified success=true", outcome, ok)
	}
}

// Enforce without a reverifier fails closed.
func TestRecoveryCodesReverify_EnforceWithoutReverifierFailsClosed(t *testing.T) {
	generated := 0
	h := NewMFAHandler(&mockMFAService{
		recoveryFn: func(_ context.Context, _ uint) ([]string, error) { generated++; return []string{"x"}, nil },
	}, nil)
	h.SetRecoveryCodesReverify("enforce", nil)
	if rr := recoveryPost(h, `{"password":"x","code":"123456"}`); rr.Code != http.StatusInternalServerError || generated != 0 {
		t.Fatalf("status %d, generated %d, want 500 and none", rr.Code, generated)
	}
}
