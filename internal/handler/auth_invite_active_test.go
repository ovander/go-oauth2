package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/service"
)

// activeAccountAuthService refuses every invite as being for an account in use.
type activeAccountAuthService struct{ *med03AuthService }

func (activeAccountAuthService) AcceptInvite(_ context.Context, _, _, _ string) (*dto.LoginResponse, error) {
	return nil, service.ErrInviteAccountActive
}

func TestAcceptInvite_ActiveAccount_Is409(t *testing.T) {
	h := NewAuthHandler(activeAccountAuthService{&med03AuthService{}}, &med03UserService{}, &med03EmailService{},
		"production", "https://auth.example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/invite",
		bytes.NewBufferString(`{"token":"t","password":"ValidPass1!"}`))
	rr := httptest.NewRecorder()
	h.AcceptInvite(rr, req)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "sign in instead") {
		t.Fatalf("AcceptInvite → %d %s, want 409 with the sign-in hint", rr.Code, rr.Body.String())
	}
}
