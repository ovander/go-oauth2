// Package migrate provides a lightweight, versioned schema migration runner.
//
// M-02 fix: ad-hoc column renames and other one-off schema fixes previously
// lived inline in bootstrap.go with no record of whether they had been applied.
// This package tracks every migration in a _schema_migrations table so each
// migration runs exactly once across any number of server restarts.
//
// Adding a new migration:
//  1. Append a Migration to the migrations slice.
//  2. Give it the next sequential ID (zero-padded four digits, e.g. "0002").
//  3. Write an idempotent Run function — it will only be called once, but
//     defensive guard clauses (HasTable, HasColumn) make rollbacks safer.
//
// Run(db) is safe to call on every startup: it is a no-op when all migrations
// have already been applied.
package migrate

import (
	"fmt"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// Migration describes a single, named schema change.
type Migration struct {
	// ID is a zero-padded sequential string used for ordering and deduplication
	// (e.g. "0001", "0002").  It must be unique and never reused.
	ID string
	// Name is a human-readable description recorded in the log.
	Name string
	// Run executes the migration inside the provided *gorm.DB.  It must be
	// idempotent: a partial failure followed by a re-run must not cause errors.
	Run func(db *gorm.DB) error
}

// migrations is the ordered list of all schema migrations.
// IMPORTANT: never remove or reorder existing entries.
var migrations = []Migration{
	{
		// M-02 fix: the blocked_ips table was originally created with an
		// inserted_at column that was later renamed to blocked_at to match
		// the model field name.  This was previously done with an inline
		// guard in bootstrap.go that ran on every startup.
		ID:   "0001",
		Name: "rename_blocked_ips.inserted_at_to_blocked_at",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("blocked_ips") {
				return nil // table does not exist yet — AutoMigrate will create it correctly
			}
			if !db.Migrator().HasColumn(&model.BlockedIP{}, "inserted_at") {
				return nil // column already renamed or was never called inserted_at
			}
			return db.Migrator().RenameColumn(&model.BlockedIP{}, "inserted_at", "blocked_at")
		},
	},
	{
		// Soft-delete unique constraint fix: the idx_users_email_active index
		// was created as a plain unique index on email, which prevents reusing
		// an email address after a user is soft-deleted (deleted_at IS NOT NULL).
		// The index must be replaced with a partial unique index that only
		// enforces uniqueness among active (non-deleted) rows.
		ID:   "0002",
		Name: "fix_users_email_unique_index_partial",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("users") {
				return nil
			}
			// Drop the plain unique index (ignore error if it doesn't exist).
			db.Exec("DROP INDEX IF EXISTS idx_users_email_active")
			// Create a partial unique index — only active rows must be unique.
			return db.Exec(
				"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_active ON users(email) WHERE deleted_at IS NULL",
			).Error
		},
	},
	{
		// MED-02 fix: the require_pkce column was added to the App model to
		// enforce PKCE (RFC 7636) on public clients.  Databases created before
		// this change do not have the column, which causes every query touching
		// the apps table to fail with "column require_pkce does not exist".
		// We add the column here with the same default (false) as the model tag
		// so that all existing apps continue to work without PKCE enforcement
		// until an admin explicitly enables it per-app.
		ID:   "0003",
		Name: "add_apps.require_pkce",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("apps") {
				return nil // table does not exist yet — AutoMigrate will create it correctly
			}
			if db.Migrator().HasColumn(&model.App{}, "require_pkce") {
				return nil // column already present — nothing to do
			}
			return db.Exec("ALTER TABLE apps ADD COLUMN require_pkce BOOLEAN NOT NULL DEFAULT FALSE").Error
		},
	},
	{
		// Public client support: add is_public flag to the apps table so that
		// SPA / mobile clients can be registered without a client_secret.
		// Existing apps default to false (confidential), preserving current
		// behaviour.  When is_public = true, no secret is generated at creation
		// time and the token endpoint never requires one; PKCE is always
		// enforced instead (RFC 6749 §2.1, RFC 7636).
		ID:   "0004",
		Name: "add_apps.is_public",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("apps") {
				return nil // table does not exist yet — AutoMigrate will create it correctly
			}
			if db.Migrator().HasColumn(&model.App{}, "is_public") {
				return nil // column already present — nothing to do
			}
			return db.Exec("ALTER TABLE apps ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT FALSE").Error
		},
	},
	{
		// Magic-link (passwordless) authentication: create the magic_link_tokens
		// table used to store single-use login tokens.
		// Columns:
		//   token_hash  — SHA-256 hex of the raw token (never stored in plaintext)
		//   user_id     — FK to users; the recipient of the magic link
		//   app_id      — FK to apps; scopes the token to one OAuth client
		//   email       — denormalised copy for per-address rate-limit queries
		//   used        — boolean flag set to TRUE once the token is redeemed
		//   used_at     — timestamp of first (only) use
		//   expires_at  — hard expiry; tokens are ignored after this point
		//   inserted_at — creation timestamp (matches the GORM model tag)
		ID:   "0005",
		Name: "create_magic_link_tokens",
		Run: func(db *gorm.DB) error {
			if db.Migrator().HasTable("magic_link_tokens") {
				return nil // table already exists — nothing to do
			}
			// GORM's db.Exec uses a prepared statement; PostgreSQL forbids
			// multiple commands in a single prepared statement (SQLSTATE 42601).
			// Each DDL statement must be executed separately.
			stmts := []string{
				`CREATE TABLE magic_link_tokens (
					id          BIGSERIAL    PRIMARY KEY,
					token_hash  VARCHAR(64)  NOT NULL,
					user_id     BIGINT       NOT NULL,
					app_id      BIGINT       NOT NULL,
					email       VARCHAR(255) NOT NULL,
					used        BOOLEAN      NOT NULL DEFAULT FALSE,
					used_at     TIMESTAMPTZ,
					expires_at  TIMESTAMPTZ  NOT NULL,
					inserted_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
					CONSTRAINT uq_magic_link_token_hash UNIQUE (token_hash)
				)`,
				`CREATE INDEX idx_magic_link_tokens_user_id    ON magic_link_tokens(user_id)`,
				`CREATE INDEX idx_magic_link_tokens_app_id     ON magic_link_tokens(app_id)`,
				`CREATE INDEX idx_magic_link_tokens_email      ON magic_link_tokens(email)`,
				`CREATE INDEX idx_magic_link_tokens_used       ON magic_link_tokens(used)`,
				`CREATE INDEX idx_magic_link_tokens_expires_at ON magic_link_tokens(expires_at)`,
			}
			for _, s := range stmts {
				if err := db.Exec(s).Error; err != nil {
					return err
				}
			}
			return nil
		},
	},
}

// schemaMigration is the GORM model for the _schema_migrations tracking table.
type schemaMigration struct {
	ID string `gorm:"primaryKey"`
}

// Run applies every pending migration in order.  Already-applied migrations are
// skipped by checking the _schema_migrations table.  The tracking table itself
// is created via AutoMigrate on first call (this is the only AutoMigrate call
// that is safe to run unconditionally because the table has no columns that
// could change across versions).
func Run(db *gorm.DB) error {
	return runWithList(db, migrations)
}

// runWithList is the implementation used by Run and by tests that inject a
// custom migration list without touching the real migrations slice.
func runWithList(db *gorm.DB, migs []Migration) error {
	// Ensure the tracking table exists.
	if err := db.AutoMigrate(&schemaMigration{}); err != nil {
		return fmt.Errorf("migrate: failed to create _schema_migrations table: %w", err)
	}

	for _, m := range migs {
		var existing schemaMigration
		if err := db.First(&existing, "id = ?", m.ID).Error; err == nil {
			// Already applied — skip.
			continue
		}

		logger.Infof("migrate: running migration %s: %s", m.ID, m.Name)

		if err := m.Run(db); err != nil {
			return fmt.Errorf("migrate: migration %s (%s) failed: %w", m.ID, m.Name, err)
		}

		if err := db.Create(&schemaMigration{ID: m.ID}).Error; err != nil {
			return fmt.Errorf("migrate: failed to record migration %s: %w", m.ID, err)
		}

		logger.Infof("migrate: ✅ migration %s applied", m.ID)
	}

	return nil
}
