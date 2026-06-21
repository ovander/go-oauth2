package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// ---------------------------------------------------------------------------
// Mock MFAService
// ---------------------------------------------------------------------------

type mockMFAService struct {
	beginFn    func(ctx context.Context, userID uint) (string, string, error)
	confirmFn  func(ctx context.Context, userID uint, code string) error
	verifyFn   func(ctx context.Context, userID uint, code string) error
	disableFn  func(ctx context.Context, userID uint) error
	enabledFn  func(ctx context.Context, userID uint) (bool, error)
	recoveryFn func(ctx context.Context, userID uint) ([]string, error)
	redeemFn   func(ctx context.Context, userID uint, code string) (bool, error)
}

func (m *mockMFAService) BeginEnrollment(ctx context.Context, userID uint) (string, string, error) {
	return m.beginFn(ctx, userID)
}
func (m *mockMFAService) ConfirmEnrollment(ctx context.Context, userID uint, code string) error {
	return m.confirmFn(ctx, userID, code)
}
func (m *mockMFAService) Verify(ctx context.Context, userID uint, code string) error {
	return m.verifyFn(ctx, userID, code)
}
func (m *mockMFAService) Disable(ctx context.Context, userID uint) error {
	return m.disableFn(ctx, userID)
}
func (m *mockMFAService) IsEnabled(ctx context.Context, userID uint) (bool, error) {
	return m.enabledFn(ctx, userID)
}
func (m *mockMFAService) GenerateRecoveryCodes(ctx context.Context, userID uint) ([]string, error) {
	return m.recoveryFn(ctx, userID)
}
func (m *mockMFAService) RedeemRecoveryCode(ctx context.Context, userID uint, code string) (bool, error) {
	return m.redeemFn(ctx, userID, code)
}

var _ service.MFAService = (*mockMFAService)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// withUser injects an authenticated user id into the request context, mirroring
// what AuthMiddleware does before the handler runs.
func withUser(r *http.Request, userID uint) *http.Request {
	ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, userID)
	return r.WithContext(ctx)
}

// ---------------------------------------------------------------------------
// Enroll
// ---------------------------------------------------------------------------

func TestMFAHandler_Enroll_Success(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{
		beginFn: func(_ context.Context, _ uint) (string, string, error) {
			return "SECRET32", "otpauth://totp/Socrate:a@b.com?secret=SECRET32", nil
		},
	})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/enroll", nil), 7)
	h.Enroll(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp dto.MFAEnrollResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Secret != "SECRET32" || !strings.HasPrefix(resp.ProvisioningURI, "otpauth://") {
		t.Fatalf("unexpected body: %+v", resp)
	}
}

func TestMFAHandler_Enroll_AlreadyEnabled(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{
		beginFn: func(_ context.Context, _ uint) (string, string, error) {
			return "", "", service.ErrMFAAlreadyEnabled
		},
	})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/enroll", nil), 7)
	h.Enroll(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
}

func TestMFAHandler_Enroll_Unauthenticated(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/profile/mfa/enroll", nil)
	h.Enroll(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Confirm
// ---------------------------------------------------------------------------

func TestMFAHandler_Confirm_Success(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{
		confirmFn: func(_ context.Context, _ uint, code string) error {
			if code != "123456" {
				t.Fatalf("unexpected code %q", code)
			}
			return nil
		},
	})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/confirm",
		strings.NewReader(`{"code":"123456"}`)), 7)
	h.Confirm(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestMFAHandler_Confirm_InvalidCode(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{
		confirmFn: func(_ context.Context, _ uint, _ string) error {
			return service.ErrMFAInvalidCode
		},
	})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/confirm",
		strings.NewReader(`{"code":"000000"}`)), 7)
	h.Confirm(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestMFAHandler_Confirm_NotEnrolled(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{
		confirmFn: func(_ context.Context, _ uint, _ string) error {
			return service.ErrMFANotEnrolled
		},
	})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/confirm",
		strings.NewReader(`{"code":"123456"}`)), 7)
	h.Confirm(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
}

func TestMFAHandler_Confirm_BadJSON(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/confirm",
		strings.NewReader(`{not json`)), 7)
	h.Confirm(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Disable
// ---------------------------------------------------------------------------

func TestMFAHandler_Disable_Success(t *testing.T) {
	called := false
	h := NewMFAHandler(&mockMFAService{
		disableFn: func(_ context.Context, _ uint) error { called = true; return nil },
	})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/disable", nil), 7)
	h.Disable(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if !called {
		t.Fatal("expected Disable to be called")
	}
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func TestMFAHandler_Status(t *testing.T) {
	for _, tc := range []struct{ enabled bool }{{true}, {false}} {
		h := NewMFAHandler(&mockMFAService{
			enabledFn: func(_ context.Context, _ uint) (bool, error) { return tc.enabled, nil },
		})

		rr := httptest.NewRecorder()
		req := withUser(httptest.NewRequest(http.MethodGet, "/api/profile/mfa", nil), 7)
		h.Status(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var resp dto.MFAStatusResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Enabled != tc.enabled {
			t.Fatalf("expected enabled=%v, got %v", tc.enabled, resp.Enabled)
		}
	}
}

func TestMFAHandler_Status_Unauthenticated(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/profile/mfa", nil)
	h.Status(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

func TestMFAHandler_RecoveryCodes_Success(t *testing.T) {
	want := []string{"aaaaa-bbbbb", "ccccc-ddddd"}
	h := NewMFAHandler(&mockMFAService{
		recoveryFn: func(_ context.Context, _ uint) ([]string, error) { return want, nil },
	})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/recovery-codes", nil), 7)
	h.RecoveryCodes(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp dto.MFARecoveryCodesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.RecoveryCodes) != len(want) {
		t.Fatalf("expected %d codes, got %d", len(want), len(resp.RecoveryCodes))
	}
}

func TestMFAHandler_RecoveryCodes_NotEnabled(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{
		recoveryFn: func(_ context.Context, _ uint) ([]string, error) {
			return nil, service.ErrMFANotEnrolled
		},
	})

	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/profile/mfa/recovery-codes", nil), 7)
	h.RecoveryCodes(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
}

func TestMFAHandler_RecoveryCodes_Unauthenticated(t *testing.T) {
	h := NewMFAHandler(&mockMFAService{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/profile/mfa/recovery-codes", nil)
	h.RecoveryCodes(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}
