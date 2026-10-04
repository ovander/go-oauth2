package migrate_test

import (
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
)

// The migration list is exercised by unit tests that check its shape (unique,
// sequential IDs and so on), but those cannot tell whether the SQL is valid.
// This one applies the whole chain to a real, empty database.
//
// It runs only when TEST_DATABASE_URL points at a scratch database — the suite
// stays runnable with no database, and anyone with one gets the coverage.
// The target database is modified, so point it at a throwaway.
func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the migration integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: glogger.Default.LogMode(glogger.Silent),
	})
	if err != nil {
		t.Fatalf("connect to the test database: %v", err)
	}
	return db
}

// Every migration applies to an empty database, and applying them twice is a
// no-op — which is the property the _schema_migrations bookkeeping exists to
// provide and the one that breaks silently if a migration is not idempotent.
func TestMigrations_ApplyToEmptyDatabase(t *testing.T) {
	db := testDB(t)

	if err := migrate.Run(db); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("second run (should be a no-op): %v", err)
	}

	for _, table := range []string{
		"rate_limit_counters",
		"dpop_replay",
		"webhook_subscriptions",
		"webhook_deliveries",
	} {
		var n int64
		if err := db.Raw("SELECT count(*) FROM " + table).Scan(&n).Error; err != nil {
			t.Errorf("table %s is not usable after migration: %v", table, err)
		}
	}
}

// B4's shared-state tables must be UNLOGGED: they carry ephemeral,
// reconstructible counters written on every rate-limited request, and the WAL
// traffic of a logged table would be pure cost. A migration that quietly
// created them logged would still pass every other test.
func TestMigrations_SharedStateTablesAreUnlogged(t *testing.T) {
	db := testDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, table := range []string{"rate_limit_counters", "dpop_replay"} {
		var persistence string
		if err := db.Raw(
			"SELECT relpersistence FROM pg_class WHERE relname = ?", table,
		).Scan(&persistence).Error; err != nil {
			t.Fatalf("read relpersistence for %s: %v", table, err)
		}
		if persistence != "u" {
			t.Errorf("%s relpersistence = %q, want %q (unlogged)", table, persistence, "u")
		}
	}
}

// 0028 adds apps.access_token_ttl_seconds on a fresh install and on an upgrade
// from a database that predates it (the column absent and 0028 not recorded).
// It runs in a database of its own: dropping a column in the shared test
// database would race with the other packages' tests.
func TestMigration0028_AccessTokenTTLColumn(t *testing.T) {
	db := scratchDB(t)
	// A fresh install creates the tables from the models (AutoMigrate), which
	// already carry the column; the numbered migrations then run on top.
	if err := db.AutoMigrate(&model.App{}); err != nil {
		t.Fatalf("automigrate apps: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	hasColumn := func() bool {
		var n int64
		db.Raw(`SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'apps' AND column_name = 'access_token_ttl_seconds'`).Scan(&n)
		return n == 1
	}
	if !hasColumn() {
		t.Fatal("fresh install: apps.access_token_ttl_seconds missing")
	}

	if err := db.Exec("ALTER TABLE apps DROP COLUMN access_token_ttl_seconds").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0028'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("upgrade run: %v", err)
	}
	if !hasColumn() {
		t.Fatal("upgrade: apps.access_token_ttl_seconds not added")
	}
}

// 0029 adds authorization_codes.auth_time, amr and acr on a fresh install and
// on an upgrade from a database that predates them.
func TestMigration0029_AuthorizationCodeAuthnColumns(t *testing.T) {
	db := scratchDB(t)
	if err := db.AutoMigrate(&model.AuthorizationCode{}); err != nil {
		t.Fatalf("automigrate authorization_codes: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	cols := func() int64 {
		var n int64
		db.Raw(`SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'authorization_codes' AND column_name IN ('auth_time', 'amr', 'acr')`).Scan(&n)
		return n
	}
	if got := cols(); got != 3 {
		t.Fatalf("fresh install: %d of the 3 columns", got)
	}

	for _, c := range []string{"auth_time", "amr", "acr"} {
		if err := db.Exec("ALTER TABLE authorization_codes DROP COLUMN " + c).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0029'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("upgrade run: %v", err)
	}
	if got := cols(); got != 3 {
		t.Fatalf("upgrade: %d of the 3 columns", got)
	}
}

// scratchDB creates an empty database next to TEST_DATABASE_URL's, for a test
// that changes the schema, and drops it at the end. It skips when the role
// may not create databases.
func scratchDB(t *testing.T) *gorm.DB {
	t.Helper()
	admin := testDB(t)
	name := fmt.Sprintf("socrate_mig_%d", time.Now().UnixNano())
	if err := admin.Exec("CREATE DATABASE " + name).Error; err != nil {
		t.Skipf("cannot create a scratch database (%v)", err)
	}
	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := gorm.Open(postgres.Open(u.String()), &gorm.Config{Logger: glogger.Default.LogMode(glogger.Silent)})
	if err != nil {
		t.Fatalf("connect to the scratch database: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error
	})
	return db
}
