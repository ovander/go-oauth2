// Package handler — the token endpoint answers an unknown client_id exactly
// like a wrong secret (401 invalid_client, RFC 6749 §5.2), so it does not
// reveal which clients exist, and keeps a 500 for a failed app lookup.
package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/service"
)

func postTokenGrantErr(t *testing.T, tokenErr error, grant string) *httptest.ResponseRecorder {
	t.Helper()
	r := buildOAuthTestRouter(&fakeOAuthSvc{tokenErr: tokenErr})
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type="+grant))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("ghost", "any-secret")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func TestToken_UnknownClient_AnsweredLikeWrongSecret(t *testing.T) {
	for _, grant := range []string{"client_credentials", "authorization_code", "refresh_token"} {
		t.Run(grant, func(t *testing.T) {
			wrongSecret := postTokenGrantErr(t, service.ErrInvalidCredentials, grant)
			unknown := postTokenGrantErr(t, fmt.Errorf("%w: client_id=ghost", service.ErrAppNotFound), grant)

			if unknown.Code != http.StatusUnauthorized {
				t.Fatalf("unknown client: status = %d, want 401; body=%s", unknown.Code, unknown.Body.String())
			}
			if !strings.Contains(unknown.Body.String(), `"invalid_client"`) {
				t.Errorf("unknown client: body = %s, want invalid_client", unknown.Body.String())
			}
			if unknown.Body.String() != wrongSecret.Body.String() || unknown.Code != wrongSecret.Code {
				t.Errorf("unknown client and wrong secret differ:\n unknown: %d %s\n wrong:   %d %s",
					unknown.Code, unknown.Body.String(), wrongSecret.Code, wrongSecret.Body.String())
			}
			if strings.Contains(unknown.Body.String(), "ghost") {
				t.Errorf("response echoes the client_id: %s", unknown.Body.String())
			}
		})
	}
}

func TestToken_AppLookupFailure_Stays500(t *testing.T) {
	rr := postTokenGrantErr(t, fmt.Errorf("token endpoint: look up client: %w", errors.New("connection refused")), "client_credentials")
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), `"server_error"`) {
		t.Fatalf("status = %d body = %s, want 500 server_error", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "connection refused") {
		t.Errorf("response leaks the internal error: %s", rr.Body.String())
	}
}
