package service

import (
	"testing"

	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// #328: a client_credentials token is sender-constrained to the DPoP key of the
// verified proof sent with the token request, like the other grants. Before
// the fix require_dpop demanded the proof but issued a plain bearer token.
func TestClientCredentials_BindsToDPoPKey(t *testing.T) {
	tests := []struct {
		name    string
		require bool
		jkt     string
		wantJKT string
	}{
		{"require_dpop with proof: bound", true, "jkt-svc", "jkt-svc"},
		{"proof sent voluntarily: bound", false, "jkt-vol", "jkt-vol"},
		{"no proof, not required: unbound", false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newHigh04Service(t, newMemUsedTokenRepo())
			app := svc.appRepo.(*crit02AppRepo).app
			hash, err := auth.HashClientSecret("correct-secret")
			if err != nil {
				t.Fatal(err)
			}
			app.ClientSecretHash = hash
			app.RequireDPoP = tt.require

			resp, err := svc.Token(ctxWithJKT(tt.jkt), ccReq(""), "test-client", "correct-secret")
			if err != nil {
				t.Fatalf("client_credentials: %v", err)
			}
			claims, err := svc.tokenService.VerifyAccessToken(resp.AccessToken)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			got := ""
			if claims.Cnf != nil {
				got = claims.Cnf.JKT
			}
			if got != tt.wantJKT {
				t.Errorf("cnf.jkt = %q, want %q", got, tt.wantJKT)
			}

			// Introspection reports the binding to resource servers.
			ir, err := svc.Introspect(ctxWithJKT(""), resp.AccessToken, "test-client")
			if err != nil || !ir.Active {
				t.Fatalf("introspect: %+v, %v", ir, err)
			}
			if tt.wantJKT == "" && ir.Cnf != nil {
				t.Errorf("introspection cnf = %+v, want none", ir.Cnf)
			}
			if tt.wantJKT != "" && (ir.Cnf == nil || ir.Cnf.JKT != tt.wantJKT) {
				t.Errorf("introspection cnf = %+v, want jkt %q", ir.Cnf, tt.wantJKT)
			}
		})
	}
}
