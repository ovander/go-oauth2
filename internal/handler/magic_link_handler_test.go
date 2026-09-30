package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
)

// ---------------------------------------------------------------------------
// Minimal mock for MagicLinkService
// ---------------------------------------------------------------------------

type mockMagicLinkService struct {
	requestFn func(ctx context.Context, email string, app *model.App) (string, error)
	verifyFn  func(ctx context.Context, req dto.MagicLinkVerifyRequest) (*dto.LoginResponse, error)
}

func (m *mockMagicLinkService) RequestMagicLink(ctx context.Context, email string, app *model.App) (string, error) {
	if m.requestFn != nil {
		return m.requestFn(ctx, email, app)
	}
	return "", nil
}

func (m *mockMagicLinkService) VerifyMagicLink(ctx context.Context, req dto.MagicLinkVerifyRequest) (*dto.LoginResponse, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, req)
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newMagicLinkHandler(svc service.MagicLinkService) *MagicLinkHandler {
	return NewMagicLinkHandler(svc, "development")
}

// stubApp is a minimal *model.App for injecting into the service-account context.
var stubApp = &model.App{ID: 1, Name: "test-app", ClientID: "app-1"}

// withServiceAccountApp injects a *model.App into the request context, simulating
// what ServiceAccountMiddleware does before calling the Request handler.
func withServiceAccountApp(r *http.Request, app *model.App) *http.Request {
	ctx := context.WithValue(r.Context(), contextkeys.ServiceAccountAppKey, app)
	return r.WithContext(ctx)
}

func doMagicRequest(handler http.HandlerFunc, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/apps/1/service/magic-link", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = withServiceAccountApp(req, stubApp)
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func doVerifyRequest(handler http.HandlerFunc, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/magic-link/verify", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Request handler tests
// ---------------------------------------------------------------------------

func TestMagicLinkHandler_Request_MissingEmail(t *testing.T) {
	h := newMagicLinkHandler(&mockMagicLinkService{})

	rr := doMagicRequest(h.Request, map[string]string{"email": ""})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing email, got %d", rr.Code)
	}
}

func TestMagicLinkHandler_Request_InvalidJSON(t *testing.T) {
	h := newMagicLinkHandler(&mockMagicLinkService{})

	req := httptest.NewRequest(http.MethodPost, "/api/apps/1/service/magic-link", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	req = withServiceAccountApp(req, stubApp)
	rr := httptest.NewRecorder()
	h.Request(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestMagicLinkHandler_Request_MissingServiceAccountContext(t *testing.T) {
	// Simulate a misconfigured route where ServiceAccountMiddleware was not applied.
	h := newMagicLinkHandler(&mockMagicLinkService{})

	b, _ := json.Marshal(map[string]string{"email": "alice@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/apps/1/service/magic-link", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// Intentionally NOT calling withServiceAccountApp — context has no app.
	rr := httptest.NewRecorder()
	h.Request(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when service account context is absent, got %d", rr.Code)
	}
}

func TestMagicLinkHandler_Request_Success_OpaqueResponse(t *testing.T) {
	svc := &mockMagicLinkService{
		requestFn: func(_ context.Context, email string, app *model.App) (string, error) {
			if email != "alice@example.com" {
				t.Errorf("unexpected email %q", email)
			}
			if app.ClientID != stubApp.ClientID {
				t.Errorf("unexpected app %q", app.ClientID)
			}
			return "rawtoken123", nil
		},
	}
	h := newMagicLinkHandler(svc)

	rr := doMagicRequest(h.Request, map[string]string{"email": "alice@example.com"})

	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202 Accepted, got %d", rr.Code)
	}

	var resp dto.MagicLinkResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Message == "" {
		t.Error("expected non-empty message in response")
	}
	// In development mode the raw token / URL is returned.
	if resp.MagicURL == "" {
		t.Error("expected magic_url in development mode response")
	}
}

func TestMagicLinkHandler_Request_RateLimited(t *testing.T) {
	svc := &mockMagicLinkService{
		requestFn: func(_ context.Context, _ string, _ *model.App) (string, error) {
			return "", service.ErrMagicLinkRateLimited
		},
	}
	h := newMagicLinkHandler(svc)

	rr := doMagicRequest(h.Request, map[string]string{"email": "alice@example.com"})

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}
}

func TestMagicLinkHandler_Request_NotConfigured_Conflict(t *testing.T) {
	// An app without a magic_link_url gets a clear 409, not the opaque 202:
	// the answer depends on the app alone, so it reveals nothing about the address.
	svc := &mockMagicLinkService{
		requestFn: func(_ context.Context, _ string, _ *model.App) (string, error) {
			return "", service.ErrMagicLinkNotConfigured
		},
	}
	h := newMagicLinkHandler(svc)

	rr := doMagicRequest(h.Request, map[string]string{"email": "alice@example.com"})

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "magic_link_url") {
		t.Errorf("body %q does not name magic_link_url", rr.Body.String())
	}
}

func TestMagicLinkHandler_Request_InternalError_StillOpaqueSuccess(t *testing.T) {
	// Internal service errors (e.g. DB down) must still return the opaque
	// 202 response so that enumeration is not possible via error timing.
	svc := &mockMagicLinkService{
		requestFn: func(_ context.Context, _ string, _ *model.App) (string, error) {
			return "", errors.New("db connection refused")
		},
	}
	h := newMagicLinkHandler(svc)

	rr := doMagicRequest(h.Request, map[string]string{"email": "alice@example.com"})

	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202 Accepted even for internal errors, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Verify handler tests
// ---------------------------------------------------------------------------

func TestMagicLinkHandler_Verify_MissingFields(t *testing.T) {
	h := newMagicLinkHandler(&mockMagicLinkService{})

	rr := doVerifyRequest(h.Verify, map[string]string{"token": ""})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", rr.Code)
	}
}

func TestMagicLinkHandler_Verify_InvalidJSON(t *testing.T) {
	h := newMagicLinkHandler(&mockMagicLinkService{})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/magic-link/verify", bytes.NewBufferString("{bad"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Verify(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestMagicLinkHandler_Verify_HappyPath(t *testing.T) {
	svc := &mockMagicLinkService{
		verifyFn: func(_ context.Context, _ dto.MagicLinkVerifyRequest) (*dto.LoginResponse, error) {
			return &dto.LoginResponse{
				AccessToken:  "access",
				RefreshToken: "refresh",
				IDToken:      "id",
				TokenType:    "Bearer",
				ExpiresIn:    900,
				UserID:       42,
				Roles:        []string{"user"},
				AppRoles:     map[string]string{},
			}, nil
		},
	}
	h := newMagicLinkHandler(svc)

	rr := doVerifyRequest(h.Verify, map[string]string{
		"token":     "abc123",
		"client_id": "app-1",
	})

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp dto.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.AccessToken != "access" {
		t.Errorf("expected access_token='access', got %q", resp.AccessToken)
	}
	if resp.UserID != 42 {
		t.Errorf("expected user_id=42, got %d", resp.UserID)
	}
}

func TestMagicLinkHandler_Verify_AlreadyUsed(t *testing.T) {
	svc := &mockMagicLinkService{
		verifyFn: func(_ context.Context, _ dto.MagicLinkVerifyRequest) (*dto.LoginResponse, error) {
			return nil, service.ErrTokenAlreadyUsed
		},
	}
	h := newMagicLinkHandler(svc)

	rr := doVerifyRequest(h.Verify, map[string]string{
		"token":     "usedtoken",
		"client_id": "app-1",
	})

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for already-used token, got %d", rr.Code)
	}
}

func TestMagicLinkHandler_Verify_InvalidToken(t *testing.T) {
	svc := &mockMagicLinkService{
		verifyFn: func(_ context.Context, _ dto.MagicLinkVerifyRequest) (*dto.LoginResponse, error) {
			return nil, service.ErrInvalidToken
		},
	}
	h := newMagicLinkHandler(svc)

	rr := doVerifyRequest(h.Verify, map[string]string{
		"token":     "badtoken",
		"client_id": "app-1",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", rr.Code)
	}
}

func TestMagicLinkHandler_Verify_AccountLocked(t *testing.T) {
	svc := &mockMagicLinkService{
		verifyFn: func(_ context.Context, _ dto.MagicLinkVerifyRequest) (*dto.LoginResponse, error) {
			return nil, service.ErrAccountLocked
		},
	}
	h := newMagicLinkHandler(svc)

	rr := doVerifyRequest(h.Verify, map[string]string{
		"token":     "validtoken",
		"client_id": "app-1",
	})

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for locked account, got %d", rr.Code)
	}
}
