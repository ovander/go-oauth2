package migrate_test

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
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

// 0035 adds authorization_codes.token_family and access_jti on a fresh
// install and on an upgrade from a database that predates them.
func TestMigration0035_AuthorizationCodeIssuedTokens(t *testing.T) {
	db := scratchDB(t)
	if err := db.AutoMigrate(&model.AuthorizationCode{}); err != nil {
		t.Fatalf("automigrate authorization_codes: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	cols := func() int64 {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'authorization_codes' AND column_name IN ('token_family', 'access_jti')`).Scan(&n).Error; err != nil {
			t.Fatalf("count the columns: %v", err)
		}
		return n
	}
	if got := cols(); got != 2 {
		t.Fatalf("fresh install: %d of the 2 columns", got)
	}

	for _, c := range []string{"token_family", "access_jti"} {
		if err := db.Exec("ALTER TABLE authorization_codes DROP COLUMN " + c).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0035'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("upgrade run: %v", err)
	}
	if got := cols(); got != 2 {
		t.Fatalf("upgrade: %d of the 2 columns", got)
	}
	var idx int64
	if err := db.Raw(`SELECT count(*) FROM pg_indexes
		WHERE tablename = 'authorization_codes' AND indexname = 'idx_authorization_codes_token_family'`).Scan(&idx).Error; err != nil {
		t.Fatalf("look up the index: %v", err)
	}
	if idx != 1 {
		t.Fatal("upgrade: the token_family index is missing")
	}
}

// 0036 drops the foreign key from security_audit_logs.app_id on an upgrade;
// a fresh install never has it (#260).
func TestMigration0036_AuditAppForeignKeyDropped(t *testing.T) {
	db := scratchDB(t)
	if err := db.AutoMigrate(&model.App{}, &model.SecurityAuditLog{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	// Every foreign key on app_id, whatever its name.
	fk := func() int64 {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM pg_constraint con
			JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey)
			WHERE con.conrelid = 'security_audit_logs'::regclass AND con.contype = 'f'
			AND att.attname = 'app_id'`).Scan(&n).Error; err != nil {
			t.Fatalf("look up the constraint: %v", err)
		}
		return n
	}
	if fk() != 0 {
		t.Fatal("fresh install: security_audit_logs.app_id has a foreign key")
	}

	// An upgraded database has the constraint a previous model created, and
	// possibly the same key under another name.
	for _, name := range []string{"fk_security_audit_logs_app", "security_audit_logs_app_id_fkey"} {
		if err := db.Exec(`ALTER TABLE security_audit_logs ADD CONSTRAINT ` + name +
			` FOREIGN KEY (app_id) REFERENCES apps(id)`).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0036'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("upgrade run: %v", err)
	}
	if fk() != 0 {
		t.Fatal("upgrade: the foreign key on security_audit_logs.app_id is still there")
	}
	// The server runs AUTO_MIGRATE after the migrations: it must not put the
	// constraint back.
	if err := db.AutoMigrate(&model.App{}, &model.SecurityAuditLog{}); err != nil {
		t.Fatalf("automigrate after the migrations: %v", err)
	}
	if fk() != 0 {
		t.Fatal("AutoMigrate re-created the foreign key on security_audit_logs.app_id")
	}
}

// 0038 drops the foreign key from admin_logs.app_id on an upgrade; a fresh
// install never has it (#260 follow-up).
func TestMigration0038_AdminLogAppForeignKeyDropped(t *testing.T) {
	db := scratchDB(t)
	// A fresh install in the server's order: the migrations run on an empty
	// database (0038 finds no admin_logs table), then AutoMigrate creates the
	// tables from the models.
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run on an empty database: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.App{}, &model.AdminLog{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	fk := func() int64 {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM pg_constraint con
			JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey)
			WHERE con.conrelid = 'admin_logs'::regclass AND con.contype = 'f'
			AND att.attname = 'app_id'`).Scan(&n).Error; err != nil {
			t.Fatalf("look up the constraint: %v", err)
		}
		return n
	}
	if fk() != 0 {
		t.Fatal("fresh install: admin_logs.app_id has a foreign key")
	}
	for _, name := range []string{"fk_admin_logs_app", "admin_logs_app_id_fkey"} {
		if err := db.Exec(`ALTER TABLE admin_logs ADD CONSTRAINT ` + name +
			` FOREIGN KEY (app_id) REFERENCES apps(id)`).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0038'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("upgrade run: %v", err)
	}
	if fk() != 0 {
		t.Fatal("upgrade: the foreign key on admin_logs.app_id is still there")
	}
	if err := db.AutoMigrate(&model.User{}, &model.App{}, &model.AdminLog{}); err != nil {
		t.Fatalf("automigrate after the migrations: %v", err)
	}
	if fk() != 0 {
		t.Fatal("AutoMigrate re-created the foreign key on admin_logs.app_id")
	}
}

// 0030 adds policy_decisions.obligations (NOT NULL, default empty) on a fresh
// install and on an upgrade, without touching the rows already logged.
func TestMigration0030_PolicyDecisionObligations(t *testing.T) {
	db := scratchDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	hasColumn := func() bool {
		var n int64
		db.Raw(`SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'policy_decisions' AND column_name = 'obligations' AND is_nullable = 'NO'`).Scan(&n)
		return n == 1
	}
	if !hasColumn() {
		t.Fatal("fresh install: policy_decisions.obligations missing or nullable")
	}

	if err := db.Exec("ALTER TABLE policy_decisions DROP COLUMN obligations").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO policy_decisions (source, mode, allow, action) VALUES ('admin_pep', 'shadow', false, 'GET /x')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0030'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("upgrade run: %v", err)
	}
	if !hasColumn() {
		t.Fatal("upgrade: policy_decisions.obligations not added")
	}
	var empty int64
	db.Raw(`SELECT count(*) FROM policy_decisions WHERE obligations = '{}'`).Scan(&empty)
	if empty != 1 {
		t.Fatalf("the existing row should read back with no obligations, got %d matching", empty)
	}
}

// 0031 adds the nullable users.invite_app_id on a fresh install and on an
// upgrade from a database that predates it, leaving existing users at NULL.
func TestMigration0031_UserInviteAppID(t *testing.T) {
	db := scratchDB(t)
	// A fresh install creates the tables from the models (AutoMigrate), which
	// already carry the column; the numbered migrations then run on top.
	if err := db.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("automigrate users: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	hasColumn := func() bool {
		var n int64
		db.Raw(`SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'users' AND column_name = 'invite_app_id' AND is_nullable = 'YES'`).Scan(&n)
		return n == 1
	}
	if !hasColumn() {
		t.Fatal("fresh install: users.invite_app_id missing or not nullable")
	}

	if err := db.Exec("ALTER TABLE users DROP COLUMN invite_app_id").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO users (name, email, hashed_password, source) VALUES ('Pending', 'pending@example.test', 'x', 'manual')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0031'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("upgrade run: %v", err)
	}
	if !hasColumn() {
		t.Fatal("upgrade: users.invite_app_id not added")
	}
	var unset int64
	db.Raw(`SELECT count(*) FROM users WHERE invite_app_id IS NULL`).Scan(&unset)
	if unset != 1 {
		t.Fatalf("the existing user should keep a NULL invite_app_id, got %d matching", unset)
	}
}

func TestMigration0032_UserMFALastStep(t *testing.T) {
	db := scratchDB(t)
	if err := db.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("automigrate users: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	hasColumn := func() bool {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'users' AND column_name = 'mfa_last_step' AND is_nullable = 'NO'
			AND column_default = '0'`).Scan(&n).Error; err != nil {
			t.Fatalf("read the users columns: %v", err)
		}
		return n == 1
	}
	if !hasColumn() {
		t.Fatal("fresh install: users.mfa_last_step missing, nullable or without default 0")
	}

	if err := db.Exec("ALTER TABLE users DROP COLUMN mfa_last_step").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO users (name, email, hashed_password, source) VALUES ('Existing', 'existing@example.test', 'x', 'manual')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0032'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("upgrade run: %v", err)
	}
	if !hasColumn() {
		t.Fatal("upgrade: users.mfa_last_step not added")
	}
	var zero int64
	if err := db.Raw(`SELECT count(*) FROM users WHERE mfa_last_step = 0`).Scan(&zero).Error; err != nil {
		t.Fatal(err)
	}
	if zero != 1 {
		t.Fatalf("the existing user should get mfa_last_step 0, got %d matching", zero)
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

func TestMigration0033_AuditChainHead(t *testing.T) {
	db := scratchDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := db.Exec(`INSERT INTO audit_chain_head (id, last_id, last_hash, mac, updated_at) VALUES (1, 0, '', 'm', now())`).Error; err != nil {
		t.Fatalf("fresh install: the head row cannot be written: %v", err)
	}
	if err := db.Exec(`INSERT INTO audit_chain_head (id, last_id, last_hash, mac, updated_at) VALUES (2, 0, '', 'm', now())`).Error; err == nil {
		t.Fatal("a second head row was accepted; the table must hold one row")
	}
	// Re-running it on an existing table keeps the head.
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0033'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	var n int64
	if err := db.Raw("SELECT count(*) FROM audit_chain_head").Scan(&n).Error; err != nil || n != 1 {
		t.Fatalf("head rows after re-run = %d (%v), want 1", n, err)
	}
}

func TestMigration0034_LoginSourceFailures(t *testing.T) {
	db := scratchDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	insert := `INSERT INTO login_source_failures (user_id, source, failed_attempts, updated_at) VALUES (1, '192.0.2.1', 1, now())`
	if err := db.Exec(insert).Error; err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	if err := db.Exec(insert).Error; err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("a second row for the same account and source: %v, want a unique violation", err)
	}
	if err := db.Exec(`INSERT INTO login_source_failures (user_id, source, failed_attempts, updated_at) VALUES (1, '192.0.2.2', 1, now())`).Error; err != nil {
		t.Fatalf("a second source for the same account: %v", err)
	}
	if err := db.Exec("UPDATE login_source_failures SET failed_attempts = 4 WHERE source = '192.0.2.1'").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DELETE FROM schema_migrations WHERE id = '0034'").Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	var n int64
	if err := db.Raw("SELECT count(*) FROM login_source_failures WHERE (source = '192.0.2.1' AND failed_attempts = 4) OR source = '192.0.2.2'").Scan(&n).Error; err != nil || n != 2 {
		t.Fatalf("rows kept by the re-run = %d (%v), want both, unchanged", n, err)
	}
}

// 0037 seeds the default alert rules (#258) on a fresh install, where the
// migrations run before the models are migrated, and on an upgrade without
// rules; an upgrade whose operators already wrote rules keeps only theirs.
func TestMigration0037_DefaultAlertRules(t *testing.T) {
	rules := func(db *gorm.DB) []model.AlertRule {
		var out []model.AlertRule
		if err := db.Order("id").Find(&out).Error; err != nil {
			t.Fatalf("list the alert rules: %v", err)
		}
		return out
	}

	// Fresh install: migrations first, on an empty database, then the models.
	db := scratchDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	if db.Migrator().HasTable("users") {
		t.Error("migration 0037 created users: it must touch alert_rules only")
	}
	if err := db.AutoMigrate(&model.User{}, &model.App{}, &model.SecurityAuditLog{}, &model.AlertRule{}, &model.TriggeredAlert{}); err != nil {
		t.Fatalf("automigrate after the migrations: %v", err)
	}
	seeded := rules(db)
	if len(seeded) != 7 {
		t.Fatalf("fresh install: %d rules, want 7", len(seeded))
	}
	// The migration created alert_rules without its foreign key to users,
	// which may not exist yet; AutoMigrate added it afterwards.
	var fks int64
	if err := db.Raw(`SELECT count(*) FROM pg_constraint WHERE conrelid = 'alert_rules'::regclass AND contype = 'f'`).Scan(&fks).Error; err != nil || fks != 1 {
		t.Errorf("fresh install: %d foreign keys on alert_rules (err %v), want created_by's", fks, err)
	}
	if err := db.Create(&model.TriggeredAlert{RuleID: seeded[0].ID, Severity: model.AlertSeverityWarning, Message: "m"}).Error; err != nil {
		t.Errorf("a seeded rule cannot be alerted on: %v", err)
	}
	emitted := map[string]bool{
		string(model.SecurityEventLoginFailed): true, string(model.SecurityEventAccountLocked): true,
		string(model.SecurityEventRefreshTokenReuse): true, string(model.SecurityEventRevokedTokenUsed): true,
		string(model.SecurityEventClientAuthFailed): true, string(model.SecurityEventAuditIntegrityViolation): true,
	}
	for _, r := range seeded {
		if r.CreatedBy != nil {
			t.Errorf("rule %q: created_by = %d, want none", r.Name, *r.CreatedBy)
		}
		if !r.Enabled || len(r.Recipients) != 0 || len(r.Actions) != 1 || r.Actions[0] != "email" {
			t.Errorf("rule %q: enabled %v, recipients %v, actions %v; want enabled, none, [email]", r.Name, r.Enabled, r.Recipients, r.Actions)
		}
		if !emitted[r.EventType] {
			t.Errorf("rule %q watches %q, an event the server does not record", r.Name, r.EventType)
		}
		if _, err := service.ParseAlertCondition(r.Condition); err != nil {
			t.Errorf("rule %q: the evaluator refuses its condition: %v", r.Name, err)
		}
	}

	// Upgrade with rules of its own: nothing is added.
	db = scratchDB(t)
	if err := db.AutoMigrate(&model.User{}, &model.AlertRule{}); err != nil {
		t.Fatal(err)
	}
	own := model.AlertRule{Name: "Ours", EventType: "login_failed", Severity: model.AlertSeverityWarning,
		Condition: map[string]interface{}{"threshold": 3, "window_minutes": 5}, Actions: []string{"webhook"}}
	if err := db.Create(&own).Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := rules(db); len(got) != 1 || got[0].Name != "Ours" {
		t.Fatalf("upgrade with rules: %d rules, want only the operator's", len(got))
	}

	// Upgrade without rules: seeded.
	db = scratchDB(t)
	if err := db.AutoMigrate(&model.User{}, &model.AlertRule{}); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := rules(db); len(got) != 7 {
		t.Fatalf("upgrade without rules: %d rules, want 7", len(got))
	}
}
