package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// p21AuthService overrides only Signup; the embedded interface is nil so any
// other call fails loudly.
type p21AuthService struct {
	service.AuthService
	err error
}

func (s *p21AuthService) Signup(_ context.Context, _ dto.SignupRequest) (*model.User, string, error) {
	return nil, "", s.err
}

func p21Signup(t *testing.T, svcErr error) string {
	t.Helper()
	h, err := NewWebHandler(&p21AuthService{err: svcErr}, nil, nil, nil, nil, "https://auth.example")
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}
	form := url.Values{
		"name": {"Alice"}, "email": {"alice@example.com"},
		"password": {"Str0ng-Passw0rd!"}, "password_confirm": {"Str0ng-Passw0rd!"},
		"client_id": {"app-1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.SignupSubmit(rr, req)
	return rr.Body.String()
}

// P2-1: the hosted signup form rendered err.Error() for an unauthenticated
// browser, so a wrapped repository/driver failure leaked verbatim.
func TestP21_SignupForm_DoesNotRenderInternalErrors(t *testing.T) {
	internal := fmt.Errorf("failed to create user: %w",
		errors.New(`pq: duplicate key value violates unique constraint "users_email_key" (SQLSTATE 23505)`))
	body := p21Signup(t, internal)
	for _, leak := range []string{"pq:", "SQLSTATE", "users_email_key", "failed to create user"} {
		if strings.Contains(body, leak) {
			t.Fatalf("signup page leaked internal error text %q", leak)
		}
	}
	if !strings.Contains(body, "Signup failed") {
		t.Fatalf("expected the generic fallback message in the page")
	}
}

func TestP21_SignupForm_MapsKnownErrorsToStaticMessages(t *testing.T) {
	cases := []struct {
		err  error
		want string
		leak string // wrapped detail that must NOT appear ("" = none)
	}{
		{fmt.Errorf("%w: user=alice@example.com id=17", service.ErrEmailAlreadyExists), "already exists", "id=17"},
		{fmt.Errorf("%w: client_id=app-1 row=missing", service.ErrAppNotFound), "not available for signup", "row=missing"},
		{auth.ErrPasswordTooShort, auth.ErrPasswordTooShort.Error(), ""},
	}
	for _, c := range cases {
		body := p21Signup(t, c.err)
		if !strings.Contains(body, c.want) {
			t.Errorf("for %v: page missing %q", c.err, c.want)
		}
		if c.leak != "" && strings.Contains(body, c.leak) {
			t.Errorf("for %v: page leaked the wrapped detail %q", c.err, c.leak)
		}
	}
}
