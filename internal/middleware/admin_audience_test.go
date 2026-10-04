package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

func audienceRequest(aud ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil)
	if aud == nil {
		return r
	}
	claims := &auth.AccessTokenClaims{RegisteredClaims: jwt.RegisteredClaims{Audience: aud}}
	return r.WithContext(context.WithValue(r.Context(), contextkeys.JWTClaimsKey, claims))
}

func TestRequireAdminAudience(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	accepted := []string{"", "admin-bff", "admin-portal"}
	cases := []struct {
		name string
		mode string
		req  *http.Request
		want int
	}{
		{"console token", AdminAudienceEnforce, audienceRequest("admin-bff"), http.StatusNoContent},
		{"admin-portal token", AdminAudienceEnforce, audienceRequest("admin-portal"), http.StatusNoContent},
		{"app token", AdminAudienceEnforce, audienceRequest("gpwa"), http.StatusForbidden},
		// aud[0] is the client: an app that registered a console's id as an
		// extra audience (AUDIENCE_MODE=dual) does not pass.
		{"console as a second audience", AdminAudienceEnforce, audienceRequest("gpwa", "admin-bff"), http.StatusForbidden},
		{"empty audience", AdminAudienceEnforce, audienceRequest(""), http.StatusForbidden},
		{"no claims (fail closed)", AdminAudienceEnforce, audienceRequest(), http.StatusForbidden},
		{"observe allows", AdminAudienceObserve, audienceRequest("gpwa"), http.StatusNoContent},
		{"off allows", AdminAudienceOff, audienceRequest("gpwa"), http.StatusNoContent},
		{"unknown mode is off", "enforced", audienceRequest("gpwa"), http.StatusNoContent},
	}
	for _, c := range cases {
		rr := httptest.NewRecorder()
		RequireAdminAudience(c.mode, accepted, nil)(ok).ServeHTTP(rr, c.req)
		if rr.Code != c.want {
			t.Errorf("%s: %d, want %d", c.name, rr.Code, c.want)
		}
	}
}
