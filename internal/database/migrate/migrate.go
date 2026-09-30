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
	"context"
	"fmt"

	"github.com/ovander/go-oauth2/internal/cluster"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/pkg/logger"
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
	{
		// RFC-007/RFC-008: correlation_id links a security_audit_logs row to the
		// request that produced it for end-to-end tracing.  Nullable and
		// additive (expand–contract): existing rows and older writers are
		// unaffected.
		ID:   "0006",
		Name: "add_security_audit_logs.correlation_id",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("security_audit_logs") {
				return nil // table does not exist yet — AutoMigrate will create it correctly
			}
			if db.Migrator().HasColumn(&model.SecurityAuditLog{}, "correlation_id") {
				return nil // column already present — nothing to do
			}
			if err := db.Exec("ALTER TABLE security_audit_logs ADD COLUMN correlation_id VARCHAR(64)").Error; err != nil {
				return err
			}
			return db.Exec("CREATE INDEX idx_security_audit_logs_correlation_id ON security_audit_logs(correlation_id)").Error
		},
	},
	{
		// RFC-007/RFC-008: correlation_id links an admin_logs row to the request
		// that produced it for end-to-end tracing.  Nullable and additive
		// (expand–contract): existing rows and older writers are unaffected.
		ID:   "0007",
		Name: "add_admin_logs.correlation_id",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("admin_logs") {
				return nil // table does not exist yet — AutoMigrate will create it correctly
			}
			if db.Migrator().HasColumn(&model.AdminLog{}, "correlation_id") {
				return nil // column already present — nothing to do
			}
			if err := db.Exec("ALTER TABLE admin_logs ADD COLUMN correlation_id VARCHAR(64)").Error; err != nil {
				return err
			}
			return db.Exec("CREATE INDEX idx_admin_logs_correlation_id ON admin_logs(correlation_id)").Error
		},
	},
	{
		// RFC-007: row_hash is a keyed HMAC over each security_audit_logs row's
		// immutable content, making the row tamper-evident.  Nullable and
		// additive (expand–contract): existing rows have no hash and older
		// writers leave it empty.
		ID:   "0008",
		Name: "add_security_audit_logs.row_hash",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("security_audit_logs") {
				return nil // table does not exist yet — AutoMigrate will create it correctly
			}
			if db.Migrator().HasColumn(&model.SecurityAuditLog{}, "row_hash") {
				return nil // column already present — nothing to do
			}
			if err := db.Exec("ALTER TABLE security_audit_logs ADD COLUMN row_hash VARCHAR(64)").Error; err != nil {
				return err
			}
			return db.Exec("CREATE INDEX idx_security_audit_logs_row_hash ON security_audit_logs(row_hash)").Error
		},
	},
	{
		// RFC-011 / EPIC-9: per-user TOTP MFA. mfa_secret stores the TOTP seed
		// encrypted at rest; mfa_enabled flags an enrolled+confirmed user.
		// Additive and nullable; existing users default to MFA disabled.
		ID:   "0009",
		Name: "add_users.mfa_secret_and_enabled",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("users") {
				return nil // table does not exist yet — AutoMigrate will create it correctly
			}
			if !db.Migrator().HasColumn(&model.User{}, "mfa_secret") {
				if err := db.Exec("ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255)").Error; err != nil {
					return err
				}
			}
			if !db.Migrator().HasColumn(&model.User{}, "mfa_enabled") {
				if err := db.Exec("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE").Error; err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		// RFC-011 / EPIC-9: one-time MFA recovery (backup) codes. Only a keyed
		// HMAC-SHA256 digest of each code is stored; codes are single-use
		// (used_at stamped on redemption).
		ID:   "0010",
		Name: "create_mfa_recovery_codes",
		Run: func(db *gorm.DB) error {
			if db.Migrator().HasTable("mfa_recovery_codes") {
				return nil // table already exists — nothing to do
			}
			stmts := []string{
				`CREATE TABLE mfa_recovery_codes (
					id          BIGSERIAL    PRIMARY KEY,
					user_id     BIGINT       NOT NULL,
					code_hash   VARCHAR(64)  NOT NULL,
					used_at     TIMESTAMPTZ,
					inserted_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
				)`,
				`CREATE INDEX idx_mfa_recovery_codes_user_id   ON mfa_recovery_codes(user_id)`,
				`CREATE INDEX idx_mfa_recovery_codes_code_hash ON mfa_recovery_codes(code_hash)`,
			}
			for _, s := range stmts {
				if err := db.Exec(s).Error; err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		// RFC-007: hash-chaining for the audit log. prev_hash links each row to
		// the previous row's row_hash so deletion/reordering is detectable, not
		// just in-place mutation. Additive and nullable; existing rows keep an
		// empty prev_hash and remain verifiable for mutation.
		ID:   "0011",
		Name: "add_security_audit_logs.prev_hash",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("security_audit_logs") {
				return nil
			}
			if db.Migrator().HasColumn(&model.SecurityAuditLog{}, "prev_hash") {
				return nil
			}
			return db.Exec("ALTER TABLE security_audit_logs ADD COLUMN prev_hash VARCHAR(64)").Error
		},
	},
	{
		// RFC-003 / EPIC-8: per-client DPoP requirement. When true, the token
		// endpoint rejects a request from this client that lacks a valid DPoP
		// proof. Additive, defaulted false; existing clients are unaffected.
		ID:   "0012",
		Name: "add_apps.require_dpop",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("apps") {
				return nil
			}
			if db.Migrator().HasColumn(&model.App{}, "require_dpop") {
				return nil
			}
			return db.Exec("ALTER TABLE apps ADD COLUMN require_dpop BOOLEAN NOT NULL DEFAULT FALSE").Error
		},
	},
	{
		// RFC 8693 / EPIC-16: per-client token-exchange capability. Both columns
		// are additive and default false, so existing clients cannot use the
		// grant until explicitly enabled.
		ID:   "0013",
		Name: "add_apps.token_exchange_flags",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("apps") {
				return nil
			}
			if !db.Migrator().HasColumn(&model.App{}, "allow_token_exchange") {
				if err := db.Exec("ALTER TABLE apps ADD COLUMN allow_token_exchange BOOLEAN NOT NULL DEFAULT FALSE").Error; err != nil {
					return err
				}
			}
			if !db.Migrator().HasColumn(&model.App{}, "allow_impersonation") {
				if err := db.Exec("ALTER TABLE apps ADD COLUMN allow_impersonation BOOLEAN NOT NULL DEFAULT FALSE").Error; err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		// RFC-001 / EPIC-7: per-client registered audiences (resource
		// identifiers) for the canonical `aud` claim. Additive text[] column
		// defaulting to an empty array, so existing clients are unaffected;
		// token issuance and enforcement are layered in by later slices.
		ID:   "0014",
		Name: "add_apps.audiences",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("apps") {
				return nil
			}
			if db.Migrator().HasColumn(&model.App{}, "audiences") {
				return nil
			}
			return db.Exec("ALTER TABLE apps ADD COLUMN audiences TEXT[] NOT NULL DEFAULT '{}'").Error
		},
	},
	{
		ID:   "0015",
		Name: "add_apps.allowed_scopes",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("apps") {
				return nil
			}
			if db.Migrator().HasColumn(&model.App{}, "allowed_scopes") {
				return nil
			}
			// Empty = no restriction, so every existing client is unaffected.
			return db.Exec("ALTER TABLE apps ADD COLUMN allowed_scopes TEXT[] NOT NULL DEFAULT '{}'").Error
		},
	},
	{
		ID:   "0016",
		Name: "add_users.attributes",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("users") {
				return nil
			}
			if db.Migrator().HasColumn(&model.User{}, "attributes") {
				return nil
			}
			// Empty object = no attributes, so every existing user is unaffected.
			return db.Exec("ALTER TABLE users ADD COLUMN attributes JSONB NOT NULL DEFAULT '{}'").Error
		},
	},
	{
		ID:   "0017",
		Name: "add_apps.claim_mappings",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("apps") {
				return nil
			}
			if db.Migrator().HasColumn(&model.App{}, "claim_mappings") {
				return nil
			}
			// Empty object = no custom claims, so every existing client keeps
			// receiving exactly the standard claim set.
			return db.Exec("ALTER TABLE apps ADD COLUMN claim_mappings JSONB NOT NULL DEFAULT '{}'").Error
		},
	},
	{
		ID:   "0018",
		Name: "create_webhook_subscriptions",
		Run: func(db *gorm.DB) error {
			if db.Migrator().HasTable(&model.WebhookSubscription{}) {
				return nil
			}
			return db.AutoMigrate(&model.WebhookSubscription{})
		},
	},
	{
		ID:   "0019",
		Name: "create_webhook_deliveries",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable(&model.WebhookDelivery{}) {
				if err := db.AutoMigrate(&model.WebhookDelivery{}); err != nil {
					return err
				}
			}
			// The dispatcher claims rows by (status, next_attempt_at); a composite
			// index keeps that scan off a sequential read as the outbox grows.
			return db.Exec(
				"CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due ON webhook_deliveries (status, next_attempt_at)",
			).Error
		},
	},
	{
		// B4: shared fixed-window rate-limit counters. UNLOGGED on purpose —
		// this is ephemeral, reconstructible state written on every rate-limited
		// request, so skipping the WAL keeps the write cost low. The tables are
		// truncated on an unclean shutdown, which is the same guarantee the
		// in-memory backend gives on restart.
		ID:   "0020",
		Name: "create_rate_limit_counters",
		Run: func(db *gorm.DB) error {
			stmts := []string{
				`CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit_counters (
					key          TEXT        NOT NULL,
					window_start TIMESTAMPTZ NOT NULL,
					count        INTEGER     NOT NULL DEFAULT 0,
					expires_at   TIMESTAMPTZ NOT NULL,
					PRIMARY KEY (key, window_start)
				)`,
				`CREATE INDEX IF NOT EXISTS idx_rate_limit_counters_expiry
					ON rate_limit_counters (expires_at)`,
			}
			for _, stmt := range stmts {
				if err := db.Exec(stmt).Error; err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		// B4: shared DPoP replay cache. Without this, a proof replayed against a
		// different instance is accepted, because only the instance that saw it
		// first remembers the jti.
		ID:   "0021",
		Name: "create_dpop_replay",
		Run: func(db *gorm.DB) error {
			stmts := []string{
				`CREATE UNLOGGED TABLE IF NOT EXISTS dpop_replay (
					jti        TEXT        PRIMARY KEY,
					expires_at TIMESTAMPTZ NOT NULL
				)`,
				`CREATE INDEX IF NOT EXISTS idx_dpop_replay_expiry
					ON dpop_replay (expires_at)`,
			}
			for _, stmt := range stmts {
				if err := db.Exec(stmt).Error; err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		// Fresh-install boot fix. Migration 0005 creates magic_link_tokens with a
		// named unique constraint (uq_magic_link_token_hash), but the GORM model
		// tags TokenHash with `uniqueIndex`, so AutoMigrate expects an index
		// named uni_magic_link_tokens_token_hash. On a brand-new database
		// migrate.Run creates the table first, AutoMigrate then finds a unique
		// constraint under the wrong name and issues
		//   ALTER TABLE magic_link_tokens DROP CONSTRAINT uni_magic_link_tokens_token_hash
		// which does not exist — SQLSTATE 42704, and the server exits.
		//
		// That is the documented first-deploy path (AUTO_MIGRATE=true on the
		// first start), so a new install could not boot. Renaming the constraint
		// to the name GORM derives makes AutoMigrate a no-op for this column.
		// Guarded both ways, so it is a no-op on databases that already agree.
		ID:   "0022",
		Name: "rename_magic_link_tokens_unique_constraint",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("magic_link_tokens") {
				return nil
			}
			var oldName, newName int64
			if err := db.Raw(
				`SELECT count(*) FROM pg_constraint
				 WHERE conrelid = 'magic_link_tokens'::regclass AND conname = 'uq_magic_link_token_hash'`,
			).Scan(&oldName).Error; err != nil {
				return err
			}
			if err := db.Raw(
				`SELECT count(*) FROM pg_constraint
				 WHERE conrelid = 'magic_link_tokens'::regclass AND conname = 'uni_magic_link_tokens_token_hash'`,
			).Scan(&newName).Error; err != nil {
				return err
			}
			if oldName == 0 || newName > 0 {
				return nil // nothing to rename, or already renamed
			}
			return db.Exec(
				`ALTER TABLE magic_link_tokens
				 RENAME CONSTRAINT uq_magic_link_token_hash TO uni_magic_link_tokens_token_hash`,
			).Error
		},
	},
	{
		// A4: the policy rule set, as immutable numbered versions. The version
		// number is the primary key, which is what makes a concurrent save from
		// a stale base fail instead of silently overwriting. Plain SQL with no
		// GORM model in the AutoMigrate list, so the two can never disagree
		// about index names (see 0022).
		ID:   "0023",
		Name: "create_policy_versions",
		Run: func(db *gorm.DB) error {
			return db.Exec(`CREATE TABLE IF NOT EXISTS policy_versions (
				version    BIGINT      PRIMARY KEY,
				rules      JSONB       NOT NULL,
				note       TEXT        NOT NULL DEFAULT '',
				created_by BIGINT,
				created_at TIMESTAMPTZ NOT NULL DEFAULT now()
			)`).Error
		},
	},
	{
		// A4: the decision log — denials, would-be denials and every
		// disagreement between the policy and the code gates. Logged, unlike
		// the B4 tables: it is evidence, and it is swept by age rather than
		// lost on a crash.
		ID:   "0024",
		Name: "create_policy_decisions",
		Run: func(db *gorm.DB) error {
			stmts := []string{
				`CREATE TABLE IF NOT EXISTS policy_decisions (
					id             BIGSERIAL   PRIMARY KEY,
					created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
					correlation_id TEXT        NOT NULL DEFAULT '',
					source         TEXT        NOT NULL,
					mode           TEXT        NOT NULL,
					enforced       BOOLEAN     NOT NULL DEFAULT false,
					allow          BOOLEAN     NOT NULL,
					divergence     TEXT        NOT NULL DEFAULT '',
					action         TEXT        NOT NULL,
					rule_id        TEXT        NOT NULL DEFAULT '',
					reason         TEXT        NOT NULL DEFAULT '',
					policy_version BIGINT      NOT NULL DEFAULT 0,
					principal_kind TEXT        NOT NULL DEFAULT '',
					principal_id   BIGINT,
					client_id      TEXT        NOT NULL DEFAULT '',
					resource_type  TEXT        NOT NULL DEFAULT '',
					resource_id    TEXT        NOT NULL DEFAULT '',
					ip_address     TEXT        NOT NULL DEFAULT '',
					status_code    INTEGER     NOT NULL DEFAULT 0
				)`,
				`CREATE INDEX IF NOT EXISTS idx_policy_decisions_created_at
					ON policy_decisions (created_at)`,
				`CREATE INDEX IF NOT EXISTS idx_policy_decisions_correlation_id
					ON policy_decisions (correlation_id) WHERE correlation_id <> ''`,
				`CREATE INDEX IF NOT EXISTS idx_policy_decisions_divergence
					ON policy_decisions (id) WHERE divergence <> ''`,
			}
			for _, stmt := range stmts {
				if err := db.Exec(stmt).Error; err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		// B5: when each scheduled job last completed, cluster-wide. The
		// advisory lock alone only stops two instances running a job at the
		// same moment; instances tick at different times, so without this a
		// job ran once per instance per interval (N key rotations instead of
		// one). Keyed by the job's advisory-lock key; one row per job.
		ID:   "0025",
		Name: "create_cluster_job_runs",
		Run: func(db *gorm.DB) error {
			return db.Exec(`CREATE TABLE IF NOT EXISTS cluster_job_runs (
				lock_key    BIGINT      PRIMARY KEY,
				last_run_at TIMESTAMPTZ NOT NULL
			)`).Error
		},
	},
	{
		// The page a magic-link email opens, per app. Nullable: NULL means magic
		// links are not configured for the app, so every existing app keeps its
		// current (unconfigured) state until an admin sets it.
		ID:   "0026",
		Name: "add_apps.magic_link_url",
		Run: func(db *gorm.DB) error {
			if !db.Migrator().HasTable("apps") {
				return nil
			}
			if db.Migrator().HasColumn(&model.App{}, "magic_link_url") {
				return nil
			}
			return db.Exec("ALTER TABLE apps ADD COLUMN magic_link_url TEXT").Error
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
//
// B5: the whole run is serialized by a PostgreSQL advisory lock, so when
// several instances start at once exactly one migrates and the others wait for
// it. Without that, two instances can pass the "already applied?" check for the
// same migration simultaneously and both execute it — at best a duplicate-object
// error that kills a healthy instance on boot, at worst a half-applied schema.
// The lock is *blocking* on purpose: an instance that gave up would go on to
// serve traffic against a schema another instance is still changing.
func Run(db *gorm.DB) error {
	return cluster.WithLock(context.Background(), db, cluster.LockMigrations, func(context.Context) error {
		return runWithList(db, migrations)
	})
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
