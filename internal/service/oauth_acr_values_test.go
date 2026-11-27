package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// ACR_VALUES_MODE: a client asking for acr_values=mfa (a step-up before a
// sensitive action) gets a code only for a second-factor sign-in under
// enforce; observe audits the shortfall; off ignores acr_values.

func TestACRValuesRequireMFA(t *testing.T) {
	for in, want := range map[string]bool{
		"": false, "pwd": false, "mfa": true, "  mfa  ": true, "mfa pwd": false, "pwd mfa": false,
		"urn:other mfa": true, "urn:other": false,
	} {
		if got := acrValuesRequireMFA(in); got != want {
			t.Errorf("acrValuesRequireMFA(%q) = %v, want %v", in, got, want)
		}
	}
}

func acrAuthorize(t *testing.T, mode, acrValues string, ev auth.AuthnEvidence) (*captureAuditRepo, error) {
	t.Helper()
	user := &model.User{ID: 42, Email: "op@example.test", IsVerified: true, Role: model.UserRoleSuperadmin}
	svc := newAuthorizeSvc(t, user)
	audit := &captureAuditRepo{}
	svc.auditRepo = audit
	svc.SetACRValuesMode(mode)
	req := authnAuthorizeReq()
	req.AcrValues = acrValues
	_, err := svc.Authorize(WithAuthnEvidence(context.Background(), ev), req, user.ID)
	return audit, err
}

var (
	pwdSignIn = auth.AuthnEvidence{AuthTime: time.Now().Unix(), AMR: []string{"pwd"}, ACR: "pwd"}
	mfaSignIn = auth.AuthnEvidence{AuthTime: time.Now().Unix(), AMR: []string{"pwd", "otp", "mfa"}, ACR: "mfa"}
)

func TestACRValues_OffIgnoresThem(t *testing.T) {
	for _, mode := range []string{"", "off", "bogus"} {
		audit, err := acrAuthorize(t, mode, "mfa", pwdSignIn)
		if err != nil || audit.last != nil {
			t.Errorf("mode %q: err %v, audited %+v; want a code and nothing audited", mode, err, audit.last)
		}
	}
}

func TestACRValues_ObserveAuditsAndIssues(t *testing.T) {
	audit, err := acrAuthorize(t, "observe", "mfa", pwdSignIn)
	if err != nil {
		t.Fatalf("observe: %v, want a code", err)
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventACRValuesUnmet || !audit.last.Success {
		t.Fatalf("observe audited %+v, want %s with success", audit.last, model.SecurityEventACRValuesUnmet)
	}
}

func TestACRValues_EnforceNeedsASecondFactor(t *testing.T) {
	audit, err := acrAuthorize(t, "enforce", "mfa", pwdSignIn)
	if !errors.Is(err, ErrACRValuesUnmet) {
		t.Fatalf("enforce, password sign-in: %v, want ErrACRValuesUnmet", err)
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventACRValuesUnmet || audit.last.Success {
		t.Fatalf("enforce audited %+v, want %s without success", audit.last, model.SecurityEventACRValuesUnmet)
	}
	// No evidence at all is no second factor either (fail closed).
	if _, err := acrAuthorize(t, "enforce", "mfa", auth.AuthnEvidence{}); !errors.Is(err, ErrACRValuesUnmet) {
		t.Errorf("enforce, no evidence: %v, want ErrACRValuesUnmet", err)
	}
	if audit, err := acrAuthorize(t, "enforce", "mfa", mfaSignIn); err != nil || audit.last != nil {
		t.Errorf("enforce, second-factor sign-in: %v, audited %+v; want a code, nothing audited", err, audit.last)
	}
	// Without acr_values, or accepting pwd too, nothing is required.
	for _, v := range []string{"", "pwd mfa", "pwd"} {
		if audit, err := acrAuthorize(t, "enforce", v, pwdSignIn); err != nil || audit.last != nil {
			t.Errorf("enforce, acr_values %q: %v, audited %+v; want a code", v, err, audit.last)
		}
	}
}
