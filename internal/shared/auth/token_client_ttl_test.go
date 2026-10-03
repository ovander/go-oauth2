package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/go-oauth2/internal/model"
)

// A client's own access-token lifetime can only shorten the server-wide one.
func TestAccessTokenTTLFor(t *testing.T) {
	ts, _ := newTestTokenService(t)
	ts.accessTokenTTL = 15 * time.Minute
	secs := func(v int) *int { return &v }
	for name, tc := range map[string]struct {
		app  *model.App
		want time.Duration
	}{
		"no app":              {nil, 15 * time.Minute},
		"no override":         {&model.App{}, 15 * time.Minute},
		"shorter":             {&model.App{AccessTokenTTLSeconds: secs(300)}, 5 * time.Minute},
		"longer is capped":    {&model.App{AccessTokenTTLSeconds: secs(7200)}, 15 * time.Minute},
		"zero is ignored":     {&model.App{AccessTokenTTLSeconds: secs(0)}, 15 * time.Minute},
		"negative is ignored": {&model.App{AccessTokenTTLSeconds: secs(-5)}, 15 * time.Minute},
	} {
		if got := ts.AccessTokenTTLFor(tc.app); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// The override reaches the tokens: a service-account token and a user token
// set issued to a 5-minute client expire after 5 minutes, and say so.
func TestClientTTL_AppliedToIssuedTokens(t *testing.T) {
	ts, _ := newTestTokenService(t)
	ts.accessTokenTTL = 15 * time.Minute
	five := 300
	app := &model.App{ID: 4, ClientID: "evidence-loop", AccessTokenTTLSeconds: &five}

	expOf := func(tok string) time.Duration {
		t.Helper()
		claims := &AccessTokenClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
			t.Fatal(err)
		}
		return claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	}

	svc, err := ts.GenerateClientCredentialsToken(app, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := expOf(svc); got != 5*time.Minute {
		t.Errorf("client_credentials token lifetime %v, want 5m", got)
	}

	set, err := ts.GenerateTokenSet(&model.User{ID: 9, Email: "u@example.test", TokenVersion: 1}, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if got := expOf(set.AccessToken); got != 5*time.Minute || set.ExpiresIn != 300 {
		t.Errorf("user access token lifetime %v / expires_in %d, want 5m / 300", got, set.ExpiresIn)
	}
}
