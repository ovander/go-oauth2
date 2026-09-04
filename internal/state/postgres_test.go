package state

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testDB connects to the database named by TEST_DATABASE_URL and creates the
// shared-state tables. Without that variable the test is skipped, so the suite
// stays runnable with no database while CI (and a developer with one) gets real
// coverage of the SQL — which is the part unit tests cannot reach.
func testDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("connect to %s: %v", dsn, err)
	}

	// Mirror migrations 0020/0021.
	stmts := []string{
		`CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit_counters (
			key          TEXT        NOT NULL,
			window_start TIMESTAMPTZ NOT NULL,
			count        INTEGER     NOT NULL DEFAULT 0,
			expires_at   TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (key, window_start)
		)`,
		`CREATE UNLOGGED TABLE IF NOT EXISTS dpop_replay (
			jti        TEXT        PRIMARY KEY,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM rate_limit_counters`)
		db.Exec(`DELETE FROM dpop_replay`)
	})
	return db
}

// uniqueKey keeps parallel or repeated runs from colliding in a shared database.
func uniqueKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
}

func TestPostgresRateLimitStore_IncrCountsAndResets(t *testing.T) {
	db := testDB(t)
	store := NewPostgresRateLimitStore(db, 2*time.Second)
	ctx := context.Background()
	key := uniqueKey(t)

	for want := 1; want <= 3; want++ {
		got, reset, err := store.Incr(ctx, key, time.Minute)
		if err != nil {
			t.Fatalf("Incr: %v", err)
		}
		if got != want {
			t.Fatalf("Incr #%d returned %d", want, got)
		}
		if !reset.After(time.Now()) {
			t.Fatalf("reset %v is not in the future", reset)
		}
	}

	count, _, err := store.Peek(ctx, key, time.Minute)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if count != 3 {
		t.Fatalf("Peek = %d, want 3", count)
	}

	// An untouched key reads as zero rather than erroring.
	count, _, err = store.Peek(ctx, uniqueKey(t), time.Minute)
	if err != nil || count != 0 {
		t.Fatalf("Peek on an unknown key = %d, %v; want 0, nil", count, err)
	}
}

// Different windows are different rows, which is what makes the counter reset.
func TestPostgresRateLimitStore_WindowsAreSeparate(t *testing.T) {
	db := testDB(t)
	store := NewPostgresRateLimitStore(db, 2*time.Second)
	ctx := context.Background()
	key := uniqueKey(t)

	if _, _, err := store.Incr(ctx, key, time.Minute); err != nil {
		t.Fatalf("Incr: %v", err)
	}
	// A different window size lands on a different boundary, hence a fresh count.
	got, _, err := store.Incr(ctx, key, time.Hour)
	if err != nil {
		t.Fatalf("Incr (hour window): %v", err)
	}
	if got != 1 {
		t.Fatalf("a different window started at %d, want 1", got)
	}
}

// The whole point of the shared store: concurrent callers — standing in for
// separate instances — must not lose counts.
func TestPostgresRateLimitStore_ConcurrentIncrDoesNotLoseCounts(t *testing.T) {
	db := testDB(t)
	store := NewPostgresRateLimitStore(db, 5*time.Second)
	ctx := context.Background()
	key := uniqueKey(t)

	const n = 50
	var wg sync.WaitGroup
	seen := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, _, err := store.Incr(ctx, key, time.Minute)
			if err != nil {
				t.Errorf("Incr: %v", err)
				return
			}
			seen[i] = c
		}(i)
	}
	wg.Wait()

	final, _, err := store.Peek(ctx, key, time.Minute)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if final != n {
		t.Fatalf("final count = %d, want %d — counts were lost under concurrency", final, n)
	}

	// Every caller must have received a distinct count: that is what lets each
	// one decide independently whether it was within the limit.
	distinct := map[int]bool{}
	for _, c := range seen {
		if c == 0 {
			continue
		}
		if distinct[c] {
			t.Fatalf("count %d was handed to two callers", c)
		}
		distinct[c] = true
	}
	if len(distinct) != n {
		t.Fatalf("%d distinct counts across %d callers", len(distinct), n)
	}
}

func TestPostgresRateLimitStore_Sweep(t *testing.T) {
	db := testDB(t)
	store := NewPostgresRateLimitStore(db, 2*time.Second)
	ctx := context.Background()

	// An already-expired row.
	if err := db.Exec(
		`INSERT INTO rate_limit_counters (key, window_start, count, expires_at) VALUES (?, ?, 1, ?)`,
		uniqueKey(t), time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour),
	).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	live := uniqueKey(t)
	if _, _, err := store.Incr(ctx, live, time.Hour); err != nil {
		t.Fatalf("Incr: %v", err)
	}

	n, err := store.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n < 1 {
		t.Fatalf("Sweep removed %d rows, want at least the expired one", n)
	}

	// The live counter survived.
	count, _, err := store.Peek(ctx, live, time.Hour)
	if err != nil || count != 1 {
		t.Fatalf("live counter after sweep = %d, %v; want 1, nil", count, err)
	}
}

// The security property: the first caller claims the jti, everyone else is told
// it is a replay — atomically, so two instances cannot both accept one proof.
func TestPostgresReplayStore_FirstUseWinsOnce(t *testing.T) {
	db := testDB(t)
	store := NewPostgresReplayStore(db, 2*time.Second)
	jti := uniqueKey(t)
	exp := time.Now().Add(time.Minute)

	if !store.CheckAndStore(jti, exp) {
		t.Fatal("the first use of a jti was rejected")
	}
	if store.CheckAndStore(jti, exp) {
		t.Fatal("a replayed jti was accepted")
	}
	if store.CheckAndStore(jti, exp) {
		t.Fatal("a replayed jti was accepted on the third attempt")
	}

	// A different jti is unaffected.
	if !store.CheckAndStore(uniqueKey(t), exp) {
		t.Fatal("an unrelated jti was rejected")
	}
}

// Exactly one of N concurrent claimants may win — this is the case that a
// SELECT-then-INSERT implementation would get wrong.
func TestPostgresReplayStore_ConcurrentFirstUse(t *testing.T) {
	db := testDB(t)
	store := NewPostgresReplayStore(db, 5*time.Second)
	jti := uniqueKey(t)
	exp := time.Now().Add(time.Minute)

	const n = 25
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.CheckAndStore(jti, exp) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("%d of %d concurrent claims were accepted, want exactly 1", accepted, n)
	}
}

// An entry that has expired may be claimed again — otherwise the table would
// reject a legitimately reused identifier forever.
func TestPostgresReplayStore_ExpiredEntryIsReclaimable(t *testing.T) {
	db := testDB(t)
	store := NewPostgresReplayStore(db, 2*time.Second)
	jti := uniqueKey(t)

	// Seed an entry that expired an hour ago.
	if err := db.Exec(
		`INSERT INTO dpop_replay (jti, expires_at) VALUES (?, ?)`,
		jti, time.Now().Add(-time.Hour),
	).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if !store.CheckAndStore(jti, time.Now().Add(time.Minute)) {
		t.Fatal("an expired entry was treated as a live replay")
	}
	// And it is live again now.
	if store.CheckAndStore(jti, time.Now().Add(time.Minute)) {
		t.Fatal("the reclaimed entry did not become live")
	}
}

func TestPostgresReplayStore_Sweep(t *testing.T) {
	db := testDB(t)
	store := NewPostgresReplayStore(db, 2*time.Second)
	ctx := context.Background()

	expired := uniqueKey(t)
	if err := db.Exec(
		`INSERT INTO dpop_replay (jti, expires_at) VALUES (?, ?)`,
		expired, time.Now().Add(-time.Hour),
	).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	live := uniqueKey(t)
	store.CheckAndStore(live, time.Now().Add(time.Hour))

	n, err := store.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n < 1 {
		t.Fatalf("Sweep removed %d rows, want at least the expired one", n)
	}

	// The live entry is still protecting against replay.
	if store.CheckAndStore(live, time.Now().Add(time.Hour)) {
		t.Fatal("the sweep removed a live entry")
	}
}

// A limiter over the real store enforces the configured limit end to end.
func TestStoreLimiter_OverPostgres(t *testing.T) {
	db := testDB(t)
	l := NewStoreLimiter(NewPostgresRateLimitStore(db, 2*time.Second), "test", 3, time.Minute)
	key := uniqueKey(t)

	for i := 1; i <= 3; i++ {
		if !l.Allow(key) {
			t.Fatalf("request %d denied under a limit of 3", i)
		}
	}
	if l.Allow(key) {
		t.Fatal("the 4th request was allowed")
	}
	if got := l.RemainingRequests(key); got != 0 {
		t.Errorf("remaining = %d, want 0", got)
	}
}

func TestSweeper_RunsEveryStore(t *testing.T) {
	db := testDB(t)
	limits := NewPostgresRateLimitStore(db, 2*time.Second)
	replay := NewPostgresReplayStore(db, 2*time.Second)

	if err := db.Exec(
		`INSERT INTO rate_limit_counters (key, window_start, count, expires_at) VALUES (?, ?, 1, ?)`,
		uniqueKey(t), time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour),
	).Error; err != nil {
		t.Fatalf("seed counter: %v", err)
	}
	if err := db.Exec(
		`INSERT INTO dpop_replay (jti, expires_at) VALUES (?, ?)`,
		uniqueKey(t), time.Now().Add(-time.Hour),
	).Error; err != nil {
		t.Fatalf("seed replay: %v", err)
	}

	NewSweeper(time.Minute, limits, replay).SweepOnce(context.Background())

	var counters, replays int64
	db.Raw(`SELECT count(*) FROM rate_limit_counters WHERE expires_at <= now()`).Scan(&counters)
	db.Raw(`SELECT count(*) FROM dpop_replay WHERE expires_at <= now()`).Scan(&replays)
	if counters != 0 || replays != 0 {
		t.Fatalf("expired rows remain after a sweep: %d counters, %d replays", counters, replays)
	}
}

// A nil store must not panic the sweeper — bootstrap passes whichever stores
// exist for the configured backend.
func TestSweeper_SkipsNilStores(t *testing.T) {
	s := NewSweeper(time.Minute, nil, nil)
	s.SweepOnce(context.Background())
	stop := s.Start()
	stop()
	stop() // idempotent
}
