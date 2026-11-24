// Package http — RFC 9449 §7.1: under DPOP_MODE=enforce a DPoP-bound token
// presented to Socrate's own APIs without a proof is refused, through the real
// admin router.
package http

import (
	nethttp "net/http"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/shared/auth/dpop"
)

func TestDPoPBinding_AdminAPIRefusesABoundTokenWithoutProof(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	users := &decideUsers{users: map[uint]*model.User{1: f.root}}
	for mode, want := range map[string]int{"enforce": nethttp.StatusUnauthorized, "observe": nethttp.StatusNotFound, "off": nethttp.StatusNotFound} {
		h := newAdminRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			f.ts, users, nil, &decideRoles{}, &decideApps{}, RouterConfig{
				DPoPMode: mode, DPoPReplayCache: cache, DPoPHTUBase: "https://id.example.com",
			})
		bound, err := f.ts.GenerateTokenSetWithDPoP(f.root, &model.App{ClientID: "admin-bff"}, string(model.AppRoleAdmin),
			"openid", nil, "", time.Now().Unix(), "some-key-thumbprint")
		if err != nil {
			t.Fatal(err)
		}
		if code := adminCall(h, bound.AccessToken); code != want {
			t.Errorf("%s: bound token as a bearer token → %d, want %d", mode, code, want)
		}
		if code := adminCall(h, rootTokenFor(t, f, "admin-bff")); code != nethttp.StatusNotFound {
			t.Errorf("%s: unbound token → %d, want it past the gate (404)", mode, code)
		}
	}
}
