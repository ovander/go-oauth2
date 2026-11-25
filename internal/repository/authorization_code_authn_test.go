package repository_test

import (
	"context"
	"errors"
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
	repo := codeRepoInTx(t)
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

// codeRepoInTx is a code repository on a migrated test database, inside a
// transaction rolled back at the end of the test.
func codeRepoInTx(t *testing.T) repository.AuthorizationCodeRepository {
	t.Helper()
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
	return repository.NewAuthorizationCodeRepository(tx)
}

// MarkAsUsedWithTokens (migration 0035) marks an unused code used together
// with the tokens it is redeemed for, keeps it until keepUntil, and refuses a
// code already used without overwriting what it recorded.
func TestAuthorizationCode_MarkAsUsedWithTokens(t *testing.T) {
	repo := codeRepoInTx(t)
	redeemer, ok := repo.(repository.AuthorizationCodeRedeemer)
	if !ok {
		t.Fatal("the GORM code repository does not record the tokens a code is redeemed for")
	}
	ctx := context.Background()
	code := &model.AuthorizationCode{Code: "redeem-" + fmt.Sprint(time.Now().UnixNano()), UserID: 1, AppID: 1, ClientID: "c",
		RedirectURI: "https://a/cb", ExpiresAt: time.Now().Add(time.Minute)}
	if err := repo.Create(ctx, code); err != nil {
		t.Fatalf("create: %v", err)
	}
	keepUntil := time.Now().Add(7 * 24 * time.Hour)
	if err := redeemer.MarkAsUsedWithTokens(ctx, code.Code, "fam-1", "jti-1", keepUntil); err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	got, err := repo.FindByCode(ctx, code.Code)
	if err != nil {
		t.Fatalf("find after redemption: %v", err)
	}
	if !got.Used || got.TokenFamily != "fam-1" || got.AccessJTI != "jti-1" || got.ExpiresAt.Before(keepUntil.Add(-time.Second)) {
		t.Fatalf("after redemption = %+v", got)
	}
	if err := redeemer.MarkAsUsedWithTokens(ctx, code.Code, "fam-2", "jti-2", time.Time{}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("second redemption = %v, want gorm.ErrRecordNotFound", err)
	}
	got, err = repo.FindByCode(ctx, code.Code)
	if err != nil {
		t.Fatalf("find after the second redemption: %v", err)
	}
	if got.TokenFamily != "fam-1" || got.AccessJTI != "jti-1" {
		t.Fatalf("a second redemption overwrote the recorded tokens: %+v", got)
	}
}

// KeepFamilyUntil extends the expiry of the used code of a refresh-token
// family, never shortens it, and leaves other codes alone.
func TestAuthorizationCode_KeepFamilyUntil(t *testing.T) {
	repo := codeRepoInTx(t)
	retainer, ok := repo.(repository.AuthorizationCodeFamilyRetainer)
	if !ok {
		t.Fatal("the GORM code repository cannot keep a family's code")
	}
	redeemer := repo.(repository.AuthorizationCodeRedeemer)
	ctx := context.Background()
	tag := fmt.Sprint(time.Now().UnixNano())
	exp := time.Now().Add(time.Minute)
	mine := &model.AuthorizationCode{Code: "fam-mine-" + tag, UserID: 1, AppID: 1, ClientID: "c", RedirectURI: "https://a/cb", ExpiresAt: exp}
	other := &model.AuthorizationCode{Code: "fam-other-" + tag, UserID: 1, AppID: 1, ClientID: "c", RedirectURI: "https://a/cb", ExpiresAt: exp}
	for _, c := range []*model.AuthorizationCode{mine, other} {
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	if err := redeemer.MarkAsUsedWithTokens(ctx, mine.Code, "family-"+tag, "jti-a-"+tag, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := redeemer.MarkAsUsedWithTokens(ctx, other.Code, "other-"+tag, "jti-b-"+tag, time.Time{}); err != nil {
		t.Fatal(err)
	}
	keep := time.Now().Add(7 * 24 * time.Hour)
	if err := retainer.KeepFamilyUntil(ctx, "family-"+tag, keep); err != nil {
		t.Fatalf("KeepFamilyUntil: %v", err)
	}
	if err := retainer.KeepFamilyUntil(ctx, "family-"+tag, time.Now()); err != nil {
		t.Fatalf("KeepFamilyUntil (earlier): %v", err)
	}
	got, err := repo.FindByCode(ctx, mine.Code)
	if err != nil || got.ExpiresAt.Before(keep.Add(-time.Second)) {
		t.Fatalf("the family's code = %+v, %v; want kept until %v", got, err, keep)
	}
	got, err = repo.FindByCode(ctx, other.Code)
	if err != nil || got.ExpiresAt.After(exp.Add(time.Second)) {
		t.Fatalf("another family's code was extended: %+v, %v", got, err)
	}
}
