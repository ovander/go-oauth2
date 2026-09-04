package state

import (
	"context"
	"errors"
	"time"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// Table names for the shared-state tables. They are UNLOGGED (see the
// migrations): this is ephemeral, reconstructible state, and skipping the WAL
// keeps the write cost of a per-request counter low. The cost is that the
// tables are truncated if the server crashes — which is exactly the same
// guarantee the in-memory backend gives on restart.
const (
	rateLimitTable = "rate_limit_counters"
	replayTable    = "dpop_replay"
)

// PostgresRateLimitStore is the shared fixed-window counter.
type PostgresRateLimitStore struct {
	db *gorm.DB
	// timeout bounds a single store round trip so a slow database degrades
	// the limiter rather than the request path.
	timeout time.Duration
}

// NewPostgresRateLimitStore builds the Postgres-backed counter store.
func NewPostgresRateLimitStore(db *gorm.DB, timeout time.Duration) *PostgresRateLimitStore {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &PostgresRateLimitStore{db: db, timeout: timeout}
}

// Incr counts one request. The insert-or-bump is a single statement, so two
// instances racing on the same key cannot lose a count: Postgres serializes the
// conflicting upserts on the primary key and each gets its own RETURNING value.
func (s *PostgresRateLimitStore) Incr(ctx context.Context, key string, window time.Duration) (int, time.Time, error) {
	start := windowStart(time.Now(), window)
	reset := start.Add(window)

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var count int
	err := s.db.WithContext(ctx).Raw(`
		INSERT INTO `+rateLimitTable+` (key, window_start, count, expires_at)
		VALUES (?, ?, 1, ?)
		ON CONFLICT (key, window_start)
		DO UPDATE SET count = `+rateLimitTable+`.count + 1
		RETURNING count`,
		key, start, reset,
	).Scan(&count).Error
	if err != nil {
		return 0, reset, err
	}
	return count, reset, nil
}

// Peek reads the current count without recording a request. A key with no row
// yet has a count of zero.
func (s *PostgresRateLimitStore) Peek(ctx context.Context, key string, window time.Duration) (int, time.Time, error) {
	start := windowStart(time.Now(), window)
	reset := start.Add(window)

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var count int
	err := s.db.WithContext(ctx).Raw(
		`SELECT COALESCE((SELECT count FROM `+rateLimitTable+` WHERE key = ? AND window_start = ?), 0)`,
		key, start,
	).Scan(&count).Error
	if err != nil {
		return 0, reset, err
	}
	return count, reset, nil
}

// Sweep deletes counters whose window has passed.
func (s *PostgresRateLimitStore) Sweep(ctx context.Context) (int64, error) {
	res := s.db.WithContext(ctx).Exec(`DELETE FROM ` + rateLimitTable + ` WHERE expires_at <= now()`)
	return res.RowsAffected, res.Error
}

// PostgresReplayStore is the shared DPoP replay cache.
type PostgresReplayStore struct {
	db      *gorm.DB
	timeout time.Duration
}

// NewPostgresReplayStore builds the Postgres-backed replay cache.
func NewPostgresReplayStore(db *gorm.DB, timeout time.Duration) *PostgresReplayStore {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &PostgresReplayStore{db: db, timeout: timeout}
}

// CheckAndStore is the atomic first-use test.
//
// The conditional upsert does the whole decision in one statement: the row is
// inserted when absent, and on conflict it is only updated when the existing
// entry has already expired. RETURNING then tells us which happened — a
// returned row means we claimed the id, no row means a live entry was already
// there, i.e. a replay. Doing this as SELECT-then-INSERT would leave a window
// where two instances both see "absent" and both accept the same proof.
//
// On a database error it returns false — a replay verdict. That is deliberate:
// this is a security control, and the operation it guards (issuing a token)
// needs the same database anyway, so failing closed costs nothing that is not
// already lost and never silently drops replay protection.
func (s *PostgresReplayStore) CheckAndStore(id string, exp time.Time) bool {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	var claimed string
	err := s.db.WithContext(ctx).Raw(`
		INSERT INTO `+replayTable+` (jti, expires_at)
		VALUES (?, ?)
		ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at
		WHERE `+replayTable+`.expires_at <= now()
		RETURNING jti`,
		id, exp,
	).Scan(&claimed).Error

	switch {
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
		logger.WithFields(logger.Fields{"error": err.Error()}).
			Error("B4: replay store unavailable — treating the proof as replayed (fail closed)")
		return false
	case claimed == "":
		// No row returned: a live entry already held this id.
		return false
	default:
		return true
	}
}

// Sweep deletes expired replay entries.
func (s *PostgresReplayStore) Sweep(ctx context.Context) (int64, error) {
	res := s.db.WithContext(ctx).Exec(`DELETE FROM ` + replayTable + ` WHERE expires_at <= now()`)
	return res.RowsAffected, res.Error
}

// Sweeper periodically evicts expired rows from the shared-state tables. The
// stores are correct without it — every read already filters on expiry — so
// this is purely to keep the tables from growing.
type Sweeper struct {
	stores []interface {
		Sweep(context.Context) (int64, error)
	}
	interval time.Duration
}

// NewSweeper builds a sweeper over the given stores. A nil store is skipped.
func NewSweeper(interval time.Duration, stores ...interface {
	Sweep(context.Context) (int64, error)
}) *Sweeper {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	live := make([]interface {
		Sweep(context.Context) (int64, error)
	}, 0, len(stores))
	for _, s := range stores {
		if s != nil {
			live = append(live, s)
		}
	}
	return &Sweeper{stores: live, interval: interval}
}

// Start runs the sweep on a timer and returns a stop function.
func (s *Sweeper) Start() func() {
	if len(s.stores) == 0 {
		return func() {}
	}

	stop := make(chan struct{})
	ticker := time.NewTicker(s.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				s.SweepOnce(context.Background())
			}
		}
	}()

	var once bool
	return func() {
		if !once {
			once = true
			close(stop)
		}
	}
}

// SweepOnce runs one sweep across every store. A failure on one store is logged
// and does not stop the others — the tables are independent.
func (s *Sweeper) SweepOnce(ctx context.Context) {
	for _, store := range s.stores {
		if n, err := store.Sweep(ctx); err != nil {
			logger.WithFields(logger.Fields{"error": err.Error()}).
				Warn("B4: shared-state sweep failed")
		} else if n > 0 {
			logger.WithFields(logger.Fields{"rows": n}).
				Debug("B4: shared-state sweep removed expired rows")
		}
	}
}
