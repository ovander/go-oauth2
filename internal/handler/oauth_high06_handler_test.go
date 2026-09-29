// Package handler — tests for the HIGH-06 state-parameter enforcement fix.
//
// HIGH-06 fix: the OAuth 2.0 authorize endpoint now requires the state
// parameter (RFC 6749 §10.12).  Requests that omit it receive a
// "invalid_request" error rather than proceeding, preventing clients from
// accidentally implementing a CSRF-vulnerable stateless authorization flow.
package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
)

// ---------------------------------------------------------------------------
// Minimal helpers reused from existing test file
// ---------------------------------------------------------------------------
//
// newCritTestHandler, critAppService, critOAuthService, critAuthService and
// critTestSecretKey are defined in oauth_crit_handler_test.go and are visible
// within this package_test file because both files share package handler.

// ---------------------------------------------------------------------------
// Stub app service that returns a valid app for the registered client ID so
// that the redirect-URI validation passes and we reach the state check.
// ---------------------------------------------------------------------------

const high06ClientID = "high06-client"

type high06AppService struct {
	// embed critAppService so all other interface methods are handled
	critAppService
}

func newHigh06AppService() *high06AppService {
	svc := &high06AppService{}
	svc.getByClientID = func(_ context.Context, clientID string) (*model.App, error) {
		if clientID == high06ClientID {
			return &model.App{
				ID:           99,
				ClientID:     clientID,
				RedirectURIs: model.StringArray{"https://client.example.com/callback"},
				Active:       true,
			}, nil
		}
		return nil, errors.New("not found")
	}
	return svc
}

// ---------------------------------------------------------------------------
// Helper: build a GET /authorize URL with the given parameters
// ---------------------------------------------------------------------------

func authorizeURL(clientID, redirectURI, responseType, state string) string {
	u := "/oauth/authorize?client_id=" + clientID +
		"&redirect_uri=" + redirectURI +
		"&response_type=" + responseType
	if state != "" {
		u += "&state=" + state
	}
	return u
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestHIGH06_Authorize_MissingState_ReturnsInvalidRequest verifies that a
// GET /oauth/authorize request without a state parameter is rejected with an
// "invalid_request" error response (rendered as an HTML error page).
func TestHIGH06_Authorize_MissingState_ReturnsInvalidRequest(t *testing.T) {
	h := newCritTestHandler(
		newHigh06AppService(),
		&critOAuthService{},
		&critAuthService{},
	)

	url := authorizeURL(
		high06ClientID,
		"https://client.example.com/callback",
		"code",
		"", // no state
	)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	body := rec.Body.String()

	// The handler must not return 302 (redirect) when state is missing.
	if rec.Code == http.StatusFound {
		t.Errorf("expected non-redirect response for missing state, got 302 (location: %s)",
			rec.Header().Get("Location"))
	}

	// The response body must mention the error code.
	if !strings.Contains(body, "invalid_request") {
		t.Errorf("expected 'invalid_request' in error response body, got:\n%s", body)
	}
}

// TestHIGH06_Authorize_EmptyState_ReturnsInvalidRequest verifies that an
// explicit empty state= query parameter is also rejected.
func TestHIGH06_Authorize_EmptyState_ReturnsInvalidRequest(t *testing.T) {
	h := newCritTestHandler(
		newHigh06AppService(),
		&critOAuthService{},
		&critAuthService{},
	)

	// Explicitly set state= (empty value — same as missing for our purposes).
	url := "/oauth/authorize?client_id=" + high06ClientID +
		"&redirect_uri=https://client.example.com/callback" +
		"&response_type=code&state="

	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	if rec.Code == http.StatusFound {
		t.Errorf("expected non-redirect for empty state, got 302")
	}
	if !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Errorf("expected 'invalid_request' in body, got: %s", rec.Body.String())
	}
}

// TestHIGH06_Authorize_WithState_ProceedsToCSRF verifies that a request that
// includes a non-empty state parameter passes the state validation and
// proceeds further (to CSRF token generation and consent page rendering).
// The response must NOT be a "state parameter is required" error.
func TestHIGH06_Authorize_WithState_ProceedsToCSRF(t *testing.T) {
	h := newCritTestHandler(
		newHigh06AppService(),
		&critOAuthService{},
		&critAuthService{},
	)

	url := authorizeURL(
		high06ClientID,
		"https://client.example.com/callback",
		"code",
		"randomcsrfstate123",
	)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "state parameter is required") {
		t.Error("state validation should pass when state is provided, but got the 'state is required' error")
	}
}

// TestHIGH06_Authorize_UnknownClient_ReturnsInvalidClient verifies that an
// unknown client_id is still rejected before reaching the state check.
func TestHIGH06_Authorize_UnknownClient_ReturnsInvalidClient(t *testing.T) {
	h := newCritTestHandler(
		newHigh06AppService(),
		&critOAuthService{},
		&critAuthService{},
	)

	url := authorizeURL("unknown-client", "https://client.example.com/callback", "code", "somestate")
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "invalid_client") {
		t.Errorf("expected 'invalid_client' for unknown client, got:\n%s", body)
	}
}
