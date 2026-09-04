package cluster

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
)

// testDB connects to TEST_DATABASE_URL, skipping when it is unset. Advisory
// locks are a PostgreSQL feature with no in-process equivalent, so these have
// to run against a real server or not at all — a mock would only assert that
// the code calls the functions it calls.
func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the advisory-lock integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: glogger.Default.LogMode(glogger.Silent),
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return db
}

// A test key well outside the range the application uses, so a stray failure
// here cannot wedge a real job's lock.
const testKey int64 = 0x7E57_0000_0000_0001

func testKeyFor(t *testing.T) int64 {
	t.Helper()
	// Derive a per-test key so tests can run in parallel without contending.
	h := testKey
	for _, c := range t.Name() {
		h = h*31 + int64(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

// The basic contract: the work runs, and the lock is released afterwards so the
// next caller can take it.
func TestTryWithLock_RunsAndReleases(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)

	var runs int
	for i := 0; i < 3; i++ {
		ran, err := TryWithLock(context.Background(), db, key, func(context.Context) error {
			runs++
			return nil
		})
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if !ran {
			t.Fatalf("attempt %d did not run; the previous call did not release the lock", i)
		}
	}
	if runs != 3 {
		t.Fatalf("job ran %d times, want 3", runs)
	}
}

// The property the whole feature rests on: while one caller holds the lock, a
// second is turned away rather than running the same job concurrently.
func TestTryWithLock_SecondCallerIsTurnedAway(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)

	holding := make(chan struct{})
	release := make(chan struct{})
	var firstRan, secondRan bool

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ran, err := TryWithLock(context.Background(), db, key, func(context.Context) error {
			firstRan = true
			close(holding)
			<-release // hold the lock until the second attempt has been made
			return nil
		})
		if err != nil {
			t.Errorf("first caller: %v", err)
		}
		if !ran {
			t.Error("first caller did not acquire the lock")
		}
	}()

	<-holding
	ran, err := TryWithLock(context.Background(), db, key, func(context.Context) error {
		secondRan = true
		return nil
	})
	close(release)
	wg.Wait()

	if err != nil {
		t.Fatalf("second caller: %v", err)
	}
	if ran || secondRan {
		t.Fatal("the second caller ran the job while the first held the lock")
	}
	if !firstRan {
		t.Fatal("the first caller never ran")
	}

	// And once the first is done, the lock is free again.
	ran, err = TryWithLock(context.Background(), db, key, nil)
	if err != nil || !ran {
		t.Fatalf("lock not released after the holder finished: ran=%v err=%v", ran, err)
	}
}

// A job that fails still releases the lock — otherwise one error would stop
// that job cluster-wide until the process restarted.
func TestTryWithLock_ReleasesAfterJobError(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)
	wantErr := errors.New("job failed")

	ran, err := TryWithLock(context.Background(), db, key, func(context.Context) error {
		return wantErr
	})
	if !ran {
		t.Fatal("job did not run")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want the job's error", err)
	}

	ran, err = TryWithLock(context.Background(), db, key, nil)
	if err != nil || !ran {
		t.Fatalf("lock was not released after a failing job: ran=%v err=%v", ran, err)
	}
}

// A panicking job must not leave the lock held either. The panic still
// propagates — swallowing it would hide a bug — but the deferred release runs
// on the way out.
func TestTryWithLock_ReleasesAfterPanic(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)

	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected the panic to propagate")
			}
		}()
		_, _ = TryWithLock(context.Background(), db, key, func(context.Context) error {
			panic("boom")
		})
	}()

	ran, err := TryWithLock(context.Background(), db, key, nil)
	if err != nil || !ran {
		t.Fatalf("lock was not released after a panicking job: ran=%v err=%v", ran, err)
	}
}

// Exactly one of N concurrent callers runs the job — the multi-instance case
// this exists for.
func TestTryWithLock_OnlyOneOfManyRuns(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)

	const n = 12
	var mu sync.Mutex
	runs := 0
	start := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := TryWithLock(context.Background(), db, key, func(context.Context) error {
				mu.Lock()
				runs++
				mu.Unlock()
				// Hold briefly so the others genuinely overlap.
				time.Sleep(50 * time.Millisecond)
				return nil
			})
			if err != nil {
				t.Errorf("caller: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if runs != 1 {
		t.Fatalf("%d of %d concurrent callers ran the job, want exactly 1", runs, n)
	}
}

// Different keys do not contend: the used-token sweep must not be blocked by
// the audit scan.
func TestTryWithLock_KeysAreIndependent(t *testing.T) {
	db := testDB(t)
	keyA := testKeyFor(t)
	keyB := keyA + 1

	holding := make(chan struct{})
	release := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = TryWithLock(context.Background(), db, keyA, func(context.Context) error {
			close(holding)
			<-release
			return nil
		})
	}()

	<-holding
	ran, err := TryWithLock(context.Background(), db, keyB, nil)
	close(release)
	wg.Wait()

	if err != nil {
		t.Fatalf("key B: %v", err)
	}
	if !ran {
		t.Fatal("key B was blocked by a lock held on key A")
	}
}

// WithLock waits rather than giving up — the behaviour migrations depend on.
func TestWithLock_WaitsForTheHolder(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)

	holding := make(chan struct{})
	release := make(chan struct{})
	order := make(chan string, 2)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = TryWithLock(context.Background(), db, key, func(context.Context) error {
			close(holding)
			<-release
			order <- "first"
			return nil
		})
	}()

	<-holding

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := WithLock(context.Background(), db, key, func(context.Context) error {
			order <- "second"
			return nil
		}); err != nil {
			t.Errorf("WithLock: %v", err)
		}
	}()

	// Give the waiter a moment to block, then let the holder go.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	close(order)

	var seen []string
	for s := range order {
		seen = append(seen, s)
	}
	if len(seen) != 2 || seen[0] != "first" || seen[1] != "second" {
		t.Fatalf("order = %v, want the waiter to run after the holder", seen)
	}
}

// The lock must not leak into the connection pool. Taking and releasing it many
// times leaves no advisory locks behind for this session — the failure mode the
// dedicated-connection design exists to prevent.
func TestTryWithLock_DoesNotLeakLocksIntoThePool(t *testing.T) {
	db := testDB(t)
	key := testKeyFor(t)

	for i := 0; i < 20; i++ {
		if _, err := TryWithLock(context.Background(), db, key, func(context.Context) error {
			return nil
		}); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	var held int64
	if err := db.Raw(
		`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1`,
		uint32(key), //nolint:gosec // G115: objid is the low 32 bits, which is what pg_locks stores
	).Scan(&held).Error; err != nil {
		t.Fatalf("inspect pg_locks: %v", err)
	}
	if held != 0 {
		t.Fatalf("%d advisory locks still held after every call returned", held)
	}
}

// A nil database is the single-instance case: it must be an error from the lock
// primitive rather than a panic, so the caller can fall back to running
// unguarded.
func TestTryWithLock_NilDatabase(t *testing.T) {
	ran, err := TryWithLock(context.Background(), nil, testKey, nil)
	if ran {
		t.Error("reported that it ran with no database")
	}
	if err == nil {
		t.Error("expected an error for a nil database")
	}
}
