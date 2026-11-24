package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// appClientIDs resolves app 1 to "gpwa" and app 2 to "ascenda"; app 3 fails.
func appClientIDs(_ context.Context, id uint) (string, error) {
	switch id {
	case 1:
		return "gpwa", nil
	case 2:
		return "ascenda", nil
	}
	return "", errors.New("record not found")
}

// appAudienceServe routes GET /api/apps/{app_id}/users through
// RequireAppAudience with a token issued to aud (no claims when aud is nil).
func appAudienceServe(mode, appID string, aud []string, onMismatch AdminAudienceFunc) int {
	r := chi.NewRouter()
	r.Route("/api/apps/{app_id}", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if aud != nil {
					claims := &auth.AccessTokenClaims{RegisteredClaims: jwt.RegisteredClaims{Audience: aud}}
					req = req.WithContext(context.WithValue(req.Context(), contextkeys.JWTClaimsKey, claims))
				}
				next.ServeHTTP(w, req)
			})
		})
		r.Use(RequireAppAudience(mode, []string{"", "admin-bff", "admin-portal"}, appClientIDs, onMismatch))
		r.Get("/users", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/apps/"+appID+"/users", nil))
	return rr.Code
}

func TestRequireAppAudience(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		appID string
		aud   []string
		want  int
	}{
		{"console token, any app", AdminAudienceEnforce, "2", []string{"admin-bff"}, http.StatusNoContent},
		{"admin-portal token", AdminAudienceEnforce, "1", []string{"admin-portal"}, http.StatusNoContent},
		{"the app's own token", AdminAudienceEnforce, "1", []string{"gpwa"}, http.StatusNoContent},
		{"another app's token", AdminAudienceEnforce, "2", []string{"gpwa"}, http.StatusForbidden},
		// aud[0] is the client: listing the app as a second audience does not pass.
		{"the app as a second audience", AdminAudienceEnforce, "2", []string{"gpwa", "ascenda"}, http.StatusForbidden},
		{"unknown app, app token", AdminAudienceEnforce, "3", []string{"gpwa"}, http.StatusForbidden},
		{"unknown app, console token", AdminAudienceEnforce, "3", []string{"admin-bff"}, http.StatusNoContent},
		{"empty audience", AdminAudienceEnforce, "1", []string{""}, http.StatusForbidden},
		{"no claims (fail closed)", AdminAudienceEnforce, "1", nil, http.StatusForbidden},
		{"observe allows", AdminAudienceObserve, "2", []string{"gpwa"}, http.StatusNoContent},
		{"off allows", AdminAudienceOff, "2", []string{"gpwa"}, http.StatusNoContent},
		{"unknown mode is off", "enforced", "2", []string{"gpwa"}, http.StatusNoContent},
	}
	for _, c := range cases {
		if got := appAudienceServe(c.mode, c.appID, c.aud, nil); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// A mismatch is reported in observe and enforce, with the token's client and
// whether it was refused; an accepted token is not reported.
func TestRequireAppAudience_ReportsMismatches(t *testing.T) {
	type report struct {
		clientID string
		refused  bool
	}
	for _, mode := range []string{AdminAudienceObserve, AdminAudienceEnforce} {
		var got []report
		sink := func(_ *http.Request, clientID string, refused bool) { got = append(got, report{clientID, refused}) }
		appAudienceServe(mode, "1", []string{"gpwa"}, sink)
		appAudienceServe(mode, "2", []string{"gpwa"}, sink)
		want := report{"gpwa", mode == AdminAudienceEnforce}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: reports %+v, want only %+v", mode, got, want)
		}
	}
}
