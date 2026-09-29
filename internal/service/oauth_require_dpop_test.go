package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
)

func ctxWithJKT(jkt string) context.Context {
	if jkt == "" {
		return context.Background()
	}
	return context.WithValue(context.Background(), contextkeys.DPoPJKTKey, jkt)
}

func TestRequireDPoP(t *testing.T) {
	tests := []struct {
		name    string
		require bool
		jkt     string
		wantErr error
	}{
		{"not required, no proof -> ok", false, "", nil},
		{"not required, proof -> ok", false, "jkt-1", nil},
		{"required, proof present -> ok", true, "jkt-1", nil},
		{"required, no proof -> error", true, "", ErrDPoPRequired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := &model.App{ClientID: "c", RequireDPoP: tc.require}
			err := requireDPoP(ctxWithJKT(tc.jkt), app)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("require=%v jkt=%q: got %v, want %v", tc.require, tc.jkt, err, tc.wantErr)
			}
		})
	}
}
