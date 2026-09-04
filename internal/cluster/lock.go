// Package cluster holds the coordination primitives that let several Socrate
// instances run against one database without duplicating work (B5 / EPIC-13).
//
// B4 made the *request-path* state shared — rate-limit counters and the DPoP
// replay cache. This package handles the other half: the background jobs. Key
// rotation, schema migration and the sweepers are all things that must happen
// exactly once across the cluster, not once per instance. Two instances
// rotating keys on the same schedule would burn through the JWKS ring twice as
// fast; two running migrations at once can deadlock or double-apply.
//
// The mechanism is PostgreSQL advisory locks, which need no schema and are
// released automatically if an instance dies.
//
// # The connection subtlety
//
// A session-level advisory lock belongs to the *connection* that took it, and
// database/sql hands out pooled connections. Calling pg_try_advisory_lock
// through the pool takes a lock on an arbitrary connection, which is then
// returned to the pool — where a later, unrelated query may run on it, and
// where the lock silently outlives the work it was meant to guard. Every
// function here therefore pins a dedicated *sql.Conn for the lock's whole
// lifetime and releases it explicitly.
package cluster

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// Advisory lock keys. They share a 64-bit namespace with every other advisory
// lock in the database, so they are fixed, distinctive constants rather than
// hashes of a string that might collide with someone else's.
//
// Never reuse or renumber these: two releases disagreeing about which key
// guards which job is the same as having no lock at all.
const (
	// LockMigrations guards schema migration. Blocking, not try: a starting
	// instance must wait for the migration to finish rather than proceed
	// against a half-migrated schema.
	LockMigrations int64 = 0x5343524D49475241 // "SCRMIGRA"
	// LockKeyRotation guards signing-key rotation.
	LockKeyRotation int64 = 0x5343524B45595242 // "SCRKEYRB"
	// LockUsedTokenSweep guards pruning of used_tokens.
	LockUsedTokenSweep int64 = 0x5343525553454454 // "SCRUSEDT"
	// LockAuditScan guards the audit-chain integrity scan.
	LockAuditScan int64 = 0x5343524155444954 // "SCRAUDIT"
	// LockStateSweep guards the B4 shared-state sweep.
	LockStateSweep int64 = 0x5343525354415445 // "SCRSTATE"
)

// TryWithLock runs fn only if this instance can take the advisory lock without
// waiting. It reports whether fn ran.
//
// This is the right shape for a periodic job: each instance tries on every
// tick, exactly one wins, and the lock is released as soon as the work is done.
// There is no long-lived leader to fail over from — if the winner dies mid-job
// its connection drops and the lock is gone, so the next tick simply elects
// someone else.
func TryWithLock(ctx context.Context, db *gorm.DB, key int64, fn func(context.Context) error) (bool, error) {
	conn, release, err := pin(ctx, db)
	if err != nil {
		return false, err
	}
	defer release()

	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired); err != nil {
		return false, fmt.Errorf("cluster: try lock %d: %w", key, err)
	}
	if !acquired {
		// Another instance is running this job. Not an error.
		return false, nil
	}
	defer unlock(conn, key)

	if fn == nil {
		return true, nil
	}
	return true, fn(ctx)
}

// WithLock runs fn once the advisory lock is available, waiting for it.
//
// Used where skipping is not acceptable — schema migration, where an instance
// that gave up would go on to serve traffic against a schema another instance
// is still changing.
func WithLock(ctx context.Context, db *gorm.DB, key int64, fn func(context.Context) error) error {
	conn, release, err := pin(ctx, db)
	if err != nil {
		return err
	}
	defer release()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		return fmt.Errorf("cluster: lock %d: %w", key, err)
	}
	defer unlock(conn, key)

	if fn == nil {
		return nil
	}
	return fn(ctx)
}

// pin takes a dedicated connection out of the pool and returns it with a
// release function. The lock lives and dies with this connection.
func pin(ctx context.Context, db *gorm.DB) (*sql.Conn, func(), error) {
	if db == nil {
		return nil, nil, fmt.Errorf("cluster: nil database handle")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: database handle: %w", err)
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: dedicated connection: %w", err)
	}
	return conn, func() { _ = conn.Close() }, nil
}

// unlock releases the advisory lock. Closing the connection would release it
// anyway, but doing it explicitly keeps the lock's lifetime obvious and returns
// a clean connection to the pool.
func unlock(conn *sql.Conn, key int64) {
	// A background context: the caller's may already be cancelled, and failing
	// to release here would hold the lock until the connection is reaped.
	if _, err := conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", key); err != nil {
		logger.WithFields(logger.Fields{
			"error": err.Error(),
			"key":   key,
		}).Warn("B5: could not release the advisory lock; it will be released when the connection closes")
	}
}
