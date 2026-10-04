package repository_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// The sign-in evidence stored on an authorization code (migration 0029)
// survives the database round trip, and a code without it reads back empty.
func TestAuthorizationCode_AuthnEvidenceRoundTrip(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.AutoMigrate(&model.AuthorizationCode{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	tx := db.Begin()
	t.Cleanup(func() { tx.Rollback() })
	repo := repository.NewAuthorizationCodeRepository(tx)
	ctx := context.Background()
	tag := fmt.Sprint(time.Now().UnixNano())

	with := &model.AuthorizationCode{Code: "with-" + tag, UserID: 1, AppID: 1, ClientID: "c", RedirectURI: "https://a/cb",
		ExpiresAt: time.Now().Add(time.Minute), AuthTime: 1791000000, AMR: model.StringArray{"pwd", "otp", "mfa"}, ACR: "mfa"}
	without := &model.AuthorizationCode{Code: "without-" + tag, UserID: 1, AppID: 1, ClientID: "c", RedirectURI: "https://a/cb",
		ExpiresAt: time.Now().Add(time.Minute)}
	for _, c := range []*model.AuthorizationCode{with, without} {
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.Code, err)
		}
	}
	got, err := repo.FindByCode(ctx, with.Code)
	if err != nil || got.AuthTime != 1791000000 || !reflect.DeepEqual([]string(got.AMR), []string{"pwd", "otp", "mfa"}) || got.ACR != "mfa" {
		t.Fatalf("with evidence = %+v, %v", got, err)
	}
	got, err = repo.FindByCode(ctx, without.Code)
	if err != nil || got.AuthTime != 0 || len(got.AMR) != 0 || got.ACR != "" {
		t.Fatalf("without evidence = %+v, %v", got, err)
	}
}
