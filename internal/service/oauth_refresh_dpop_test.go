package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
)

func TestVerifyRefreshDPoPBinding(t *testing.T) {
	tests := []struct {
		name    string
		cnfJKT  string
		proof   string // jkt on context ("" = none)
		wantErr error
	}{
		{"unbound token, no proof -> ok", "", "", nil},
		{"unbound token, with proof -> ok", "", "jkt-1", nil},
		{"bound token, matching proof -> ok", "jkt-1", "jkt-1", nil},
		{"bound token, no proof -> mismatch", "jkt-1", "", ErrDPoPKeyMismatch},
		{"bound token, wrong proof -> mismatch", "jkt-1", "jkt-2", ErrDPoPKeyMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.proof != "" {
				ctx = context.WithValue(ctx, contextkeys.DPoPJKTKey, tc.proof)
			}
			err := verifyRefreshDPoPBinding(ctx, tc.cnfJKT)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("cnf=%q proof=%q: got %v, want %v", tc.cnfJKT, tc.proof, err, tc.wantErr)
			}
		})
	}
}
