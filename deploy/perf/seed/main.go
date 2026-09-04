// Command seed creates the fixtures the k6 performance scenarios need (B6):
// one confidential client, one public client, and a verified user with a role
// in both.
//
// It writes directly to the database rather than driving the admin API, because
// the admin API needs an authenticated superadmin, which needs a login, which
// needs a client — a bootstrapping loop that has nothing to do with what we are
// measuring.
//
// It is idempotent: re-running replaces the fixtures. Point it at a scratch
// database — DATABASE_URL is modified, and the fixture credentials below are
// public knowledge by construction.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
)

// Fixture credentials. These are deliberately fixed and well-known so the k6
// scenarios need no coordination with this program; they must never be seeded
// into anything but a throwaway performance database.
const (
	confidentialClientID = "perf-client"
	confidentialSecret   = "perf-client-secret-value-0123456789" //nolint:gosec // G101: fixture for a scratch perf database
	publicClientID       = "perf-public"
	userEmail            = "perf@example.test"
	userPassword         = "PerfBaseline!2026x" //nolint:gosec // G101: fixture for a scratch perf database
	redirectURI          = "http://localhost:9999/cb"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: glogger.Default.LogMode(glogger.Silent),
	})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}

	if err := reset(db); err != nil {
		log.Fatalf("reset fixtures: %v", err)
	}

	now := time.Now()

	secretHash, err := auth.HashClientSecret(confidentialSecret)
	if err != nil {
		log.Fatalf("hash client secret: %v", err)
	}
	confidential := &model.App{
		Name: "perf (confidential)", ClientID: confidentialClientID, ClientSecretHash: secretHash,
		Active: true, RedirectURIs: model.StringArray{redirectURI},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.Create(confidential).Error; err != nil {
		log.Fatalf("create confidential client: %v", err)
	}

	// The public client is what token_refresh runs against: it has no secret,
	// so its token calls are not bcrypt-bound and the scenario measures the
	// refresh path rather than client-secret verification.
	public := &model.App{
		Name: "perf (public)", ClientID: publicClientID, IsPublic: true, RequirePKCE: true,
		Active: true, RedirectURIs: model.StringArray{redirectURI},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.Create(public).Error; err != nil {
		log.Fatalf("create public client: %v", err)
	}

	passwordHash, err := auth.HashPassword(userPassword)
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		Name: "Perf User", Email: userEmail, HashedPassword: passwordHash,
		IsVerified: true, Role: model.UserRoleUser, TokenVersion: 1, Source: "perf-seed",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.Create(user).Error; err != nil {
		log.Fatalf("create user: %v", err)
	}

	// The user needs a role in each app to obtain tokens for it.
	for _, app := range []*model.App{confidential, public} {
		role := &model.UserAppRole{
			UserID: user.ID, AppID: app.ID, Role: "user",
			CreatedAt: now, UpdatedAt: now,
		}
		if err := db.Create(role).Error; err != nil {
			log.Fatalf("grant role in %s: %v", app.ClientID, err)
		}
	}

	fmt.Printf("seeded: confidential=%s public=%s user=%s\n",
		confidentialClientID, publicClientID, userEmail)
}

// reset removes any previous fixtures, respecting the foreign keys that
// reference them. Audit rows accumulate across runs and point at the app, so
// they have to go first.
func reset(db *gorm.DB) error {
	stmts := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM security_audit_logs WHERE app_id IN (SELECT id FROM apps WHERE client_id IN (?, ?))`,
			[]any{confidentialClientID, publicClientID}},
		{`DELETE FROM security_audit_logs WHERE user_id IN (SELECT id FROM users WHERE email = ?)`,
			[]any{userEmail}},
		{`DELETE FROM user_app_roles WHERE app_id IN (SELECT id FROM apps WHERE client_id IN (?, ?))`,
			[]any{confidentialClientID, publicClientID}},
		{`DELETE FROM user_app_roles WHERE user_id IN (SELECT id FROM users WHERE email = ?)`,
			[]any{userEmail}},
		{`DELETE FROM apps WHERE client_id IN (?, ?)`,
			[]any{confidentialClientID, publicClientID}},
		{`DELETE FROM users WHERE email = ?`, []any{userEmail}},
	}
	for _, s := range stmts {
		if err := db.Exec(s.sql, s.args...).Error; err != nil {
			return fmt.Errorf("%s: %w", s.sql, err)
		}
	}
	return nil
}
