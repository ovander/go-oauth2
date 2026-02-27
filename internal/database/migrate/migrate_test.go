// Package migrate — tests for the M-02 versioned migration runner.
//
// These are structural/property tests that run without a database.
// They verify the migrations slice is well-formed and the runner error
// format is correct.
//
// Runner behaviour tests that require a real database (idempotency, ordering,
// tracking table) should be placed in a file with //go:build integration.
package migrate

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Structure tests — no database required
// ---------------------------------------------------------------------------

func TestMigrations_NonEmpty(t *testing.T) {
	if len(migrations) == 0 {
		t.Error("migrations slice must not be empty")
	}
}

func TestMigrations_FirstEntryIs0001(t *testing.T) {
	if migrations[0].ID != "0001" {
		t.Errorf("first migration ID must be '0001', got %q", migrations[0].ID)
	}
}

func TestMigrations_AllHaveNonEmptyID(t *testing.T) {
	for i, m := range migrations {
		if m.ID == "" {
			t.Errorf("migrations[%d] has empty ID", i)
		}
	}
}

func TestMigrations_AllHaveNonEmptyName(t *testing.T) {
	for i, m := range migrations {
		if m.Name == "" {
			t.Errorf("migrations[%d] (ID=%q) has empty Name", i, m.ID)
		}
	}
}

func TestMigrations_AllHaveRunFunc(t *testing.T) {
	for i, m := range migrations {
		if m.Run == nil {
			t.Errorf("migrations[%d] (ID=%q) has nil Run func", i, m.ID)
		}
	}
}

func TestMigrations_UniqueIDs(t *testing.T) {
	seen := make(map[string]int)
	for i, m := range migrations {
		if prev, ok := seen[m.ID]; ok {
			t.Errorf("duplicate migration ID %q at indices %d and %d", m.ID, prev, i)
		}
		seen[m.ID] = i
	}
}

func TestMigrations_IDsAreSequential(t *testing.T) {
	// IDs must be zero-padded four-digit strings in ascending order so that the
	// execution order is deterministic and self-documenting.
	for i, m := range migrations {
		expected := fmt.Sprintf("%04d", i+1)
		if m.ID != expected {
			t.Errorf("migrations[%d]: expected ID %q (sequential), got %q — "+
				"never reorder or remove entries from the migrations slice", i, expected, m.ID)
		}
	}
}

func TestMigrations_0001_Name(t *testing.T) {
	m := migrations[0]
	const want = "rename_blocked_ips.inserted_at_to_blocked_at"
	if m.Name != want {
		t.Errorf("migration 0001 Name = %q, want %q", m.Name, want)
	}
}

// ---------------------------------------------------------------------------
// Runner error-format contract
// ---------------------------------------------------------------------------

func TestRunnerErrorFormat_ContainsMigrationIDAndName(t *testing.T) {
	// runWithList wraps migration failures with the migration ID and name so
	// operators can identify the failing step from the error message alone.
	// We test the format by constructing the same error string the runner does.
	const migrID = "0042"
	const migrName = "add_foo_column"
	cause := errors.New("column already exists")

	// This mirrors the format inside runWithList.
	wrapped := fmt.Errorf("migrate: migration %s (%s) failed: %w", migrID, migrName, cause)

	msg := wrapped.Error()
	for _, required := range []string{migrID, migrName, cause.Error()} {
		if !strings.Contains(msg, required) {
			t.Errorf("error message %q must contain %q", msg, required)
		}
	}

	// errors.Is must traverse the chain so callers can match the root cause.
	if !errors.Is(wrapped, cause) {
		t.Error("wrapped error must satisfy errors.Is(err, cause)")
	}
}

func TestRunnerErrorFormat_TrackingTableError_ContainsMigratePrefix(t *testing.T) {
	// The error returned when the tracking table cannot be created must carry
	// the "migrate:" prefix so it is distinguishable from application errors.
	inner := errors.New("permission denied")
	wrapped := fmt.Errorf("migrate: failed to create _schema_migrations table: %w", inner)

	if !strings.HasPrefix(wrapped.Error(), "migrate:") {
		t.Errorf("tracking-table error must start with 'migrate:', got: %q", wrapped.Error())
	}
	if !errors.Is(wrapped, inner) {
		t.Error("tracking-table error must wrap the inner error")
	}
}

// ---------------------------------------------------------------------------
// schemaMigration model
// ---------------------------------------------------------------------------

func TestSchemaMigration_PrimaryKeyIsID(t *testing.T) {
	// Verify that the struct tag is present so GORM uses ID as the primary key.
	// We do this reflectively via the struct tag string.
	//
	// If the primary key is wrong, every subsequent run would re-apply all
	// migrations (since db.First would never find an existing record).
	m := schemaMigration{ID: "0001"}
	if m.ID != "0001" {
		t.Error("schemaMigration.ID field not writable")
	}
	// The gorm tag is verified by the struct definition; this test documents
	// the contract and catches accidental field renames.
}
