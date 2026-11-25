package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/repository"
)

// #403: the per-account, per-source failure counts on Postgres.
func TestLoginSourceFailures(t *testing.T) {
	db := auditScratchDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := repository.NewLoginSourceFailureRepository(db)
	ctx := context.Background()
	const window = time.Hour

	for want := 1; want <= 3; want++ {
		n, err := repo.RecordFailure(ctx, 5, "198.51.100.7", window)
		if err != nil || n != want {
			t.Fatalf("failure %d: (%d, %v)", want, n, err)
		}
	}
	// Another source and another account count apart.
	if n, _ := repo.RecordFailure(ctx, 5, "203.0.113.9", window); n != 1 {
		t.Fatalf("another source: %d, want 1", n)
	}
	if n, _ := repo.RecordFailure(ctx, 6, "198.51.100.7", window); n != 1 {
		t.Fatalf("another account: %d, want 1", n)
	}
	// A count whose last failure is older than the window starts again.
	if err := db.Exec(`UPDATE login_source_failures SET updated_at = now() - interval '2 hours' WHERE user_id = 5 AND source = '198.51.100.7'`).Error; err != nil {
		t.Fatal(err)
	}
	if n, _ := repo.RecordFailure(ctx, 5, "198.51.100.7", window); n != 1 {
		t.Fatalf("after the window: %d, want 1", n)
	}

	// Lock, read, expire.
	if until, err := repo.LockedUntil(ctx, 5, "198.51.100.7"); err != nil || until != nil {
		t.Fatalf("not locked yet: (%v, %v)", until, err)
	}
	if err := repo.Lock(ctx, 5, "198.51.100.7", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if until, err := repo.LockedUntil(ctx, 5, "198.51.100.7"); err != nil || until == nil {
		t.Fatalf("locked: (%v, %v)", until, err)
	}
	if until, err := repo.LockedUntil(ctx, 5, "203.0.113.9"); err != nil || until != nil {
		t.Fatalf("the lock leaked to another source: (%v, %v)", until, err)
	}
	// A success does not lift a lock in force, and a second lock never
	// shortens it.
	if err := repo.Reset(ctx, 5, "198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Lock(ctx, 5, "198.51.100.7", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if until, err := repo.LockedUntil(ctx, 5, "198.51.100.7"); err != nil || until == nil || time.Until(*until) < 30*time.Second {
		t.Fatalf("lock after a reset and a shorter lock: (%v, %v), want the original minute", until, err)
	}
	if n, _ := repo.RecordFailure(ctx, 5, "198.51.100.7", window); n != 1 {
		t.Fatalf("a lock starts the count again: %d, want 1", n)
	}
	if err := db.Exec(`UPDATE login_source_failures SET locked_until = now() - interval '1 second' WHERE user_id = 5 AND source = '198.51.100.7'`).Error; err != nil {
		t.Fatal(err)
	}
	if until, err := repo.LockedUntil(ctx, 5, "198.51.100.7"); err != nil || until != nil {
		t.Fatalf("an expired lock is still in force: (%v, %v)", until, err)
	}

	// Reset and the sweep.
	if err := repo.Reset(ctx, 6, "198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Lock(ctx, 7, "192.0.2.1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := repo.DeleteStale(ctx, time.Now().Add(time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("DeleteStale = (%d, %v), want 2: both rows of user 5, not the lock in force", n, err)
	}
	var left int64
	if err := db.Raw(`SELECT count(*) FROM login_source_failures`).Scan(&left).Error; err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Fatalf("%d rows left, want the one holding a lock", left)
	}
}
