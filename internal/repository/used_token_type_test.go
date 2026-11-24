package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// #365: the store says how a token was used, so a rotated refresh token is
// told apart from a revoked one.
func TestUsedTokenType(t *testing.T) {
	db := auditScratchDB(t)
	if err := db.AutoMigrate(&model.UsedToken{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	repo := repository.NewUsedTokenRepository(db)
	reader, ok := repo.(repository.UsedTokenTypeReader)
	if !ok {
		t.Fatal("the used-token repository does not implement UsedTokenTypeReader")
	}
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	if err := repo.MarkAsUsed(ctx, "rotated-jti", "refresh", 1, exp); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkAsUsed(ctx, "revoked-jti", "revoked", 1, exp); err != nil {
		t.Fatal(err)
	}
	for jti, want := range map[string]string{"rotated-jti": "refresh", "revoked-jti": "revoked", "unused-jti": ""} {
		got, err := reader.UsedTokenType(ctx, jti)
		if err != nil || got != want {
			t.Errorf("UsedTokenType(%s) = (%q, %v), want %q", jti, got, err, want)
		}
	}
}
