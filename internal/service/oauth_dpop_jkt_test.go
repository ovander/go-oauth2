package service

import (
	"context"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
)

func TestDPoPJKTFromContext(t *testing.T) {
	if got := dpopJKTFromContext(context.Background()); got != "" {
		t.Errorf("absent key: got %q, want empty", got)
	}
	ctx := context.WithValue(context.Background(), contextkeys.DPoPJKTKey, "jkt-123")
	if got := dpopJKTFromContext(ctx); got != "jkt-123" {
		t.Errorf("present key: got %q, want jkt-123", got)
	}
	// Wrong type must not panic and must yield empty.
	ctx = context.WithValue(context.Background(), contextkeys.DPoPJKTKey, 42)
	if got := dpopJKTFromContext(ctx); got != "" {
		t.Errorf("wrong type: got %q, want empty", got)
	}
}
