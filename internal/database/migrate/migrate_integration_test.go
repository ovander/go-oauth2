package migrate_test

import (
	"os"
	"testing"

	"github.com/ovander/go-oauth2/internal/database/migrate"
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
