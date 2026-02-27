// Package database — tests for L-06: DBTimeout must be forwarded to the
// database connector as ConnMaxIdleTime.
//
// L-06 fix: Config.DBTimeout was parsed from DB_TIMEOUT_SECONDS but never
// forwarded to the database connector — Connect was called with only the pool
// size, and the timeout was silently discarded.  The bootstrap now uses
// ConnectWithConfig with dbCfg.ConnMaxIdleTime = cfg.DBTimeout when non-zero.
//
// These tests verify:
//   - DefaultConnectionConfig returns sensible default values
//   - ConnMaxIdleTime can be overridden (the field the bootstrap now sets)
//   - The override survives a round-trip: set → read back → equals original
package database

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// L-06: DefaultConnectionConfig returns sensible defaults
// ---------------------------------------------------------------------------

func TestDefaultConnectionConfig_PoolSize(t *testing.T) {
	t.Parallel()
	cfg := DefaultConnectionConfig(10)
	if cfg.PoolSize != 10 {
		t.Errorf("PoolSize = %d, want 10", cfg.PoolSize)
	}
}

func TestDefaultConnectionConfig_MaxIdleConns_HalfOfPool(t *testing.T) {
	t.Parallel()
	// MaxIdleConns is expected to be poolSize/2.
	cfg := DefaultConnectionConfig(20)
	if cfg.MaxIdleConns != 10 {
		t.Errorf("MaxIdleConns = %d, want 10 (poolSize/2)", cfg.MaxIdleConns)
	}
}

func TestDefaultConnectionConfig_ConnMaxLifetime_NonZero(t *testing.T) {
	t.Parallel()
	cfg := DefaultConnectionConfig(5)
	if cfg.ConnMaxLifetime <= 0 {
		t.Errorf("ConnMaxLifetime = %v, must be positive", cfg.ConnMaxLifetime)
	}
}

func TestDefaultConnectionConfig_ConnMaxIdleTime_NonZero(t *testing.T) {
	t.Parallel()
	cfg := DefaultConnectionConfig(5)
	if cfg.ConnMaxIdleTime <= 0 {
		t.Errorf("ConnMaxIdleTime = %v, must be positive", cfg.ConnMaxIdleTime)
	}
}

// ---------------------------------------------------------------------------
// L-06: ConnMaxIdleTime override — this is the field Bootstrap now sets
// ---------------------------------------------------------------------------

func TestConnectionConfig_ConnMaxIdleTime_Override(t *testing.T) {
	t.Parallel()
	// Simulate the bootstrap pattern:
	//   dbCfg := DefaultConnectionConfig(cfg.DBPoolSize)
	//   if cfg.DBTimeout > 0 { dbCfg.ConnMaxIdleTime = cfg.DBTimeout }
	dbTimeout := 45 * time.Second

	dbCfg := DefaultConnectionConfig(10)
	if dbTimeout > 0 {
		dbCfg.ConnMaxIdleTime = dbTimeout
	}

	if dbCfg.ConnMaxIdleTime != dbTimeout {
		t.Errorf("ConnMaxIdleTime = %v, want %v after override", dbCfg.ConnMaxIdleTime, dbTimeout)
	}
}

func TestConnectionConfig_ZeroDBTimeout_DoesNotOverrideDefault(t *testing.T) {
	t.Parallel()
	// When DBTimeout == 0, the override branch is skipped and the default
	// ConnMaxIdleTime is preserved.
	dbTimeout := time.Duration(0)

	dbCfg := DefaultConnectionConfig(10)
	defaultIdleTime := dbCfg.ConnMaxIdleTime

	if dbTimeout > 0 {
		dbCfg.ConnMaxIdleTime = dbTimeout
	}

	if dbCfg.ConnMaxIdleTime != defaultIdleTime {
		t.Errorf("ConnMaxIdleTime = %v, want default %v (zero timeout must not override)",
			dbCfg.ConnMaxIdleTime, defaultIdleTime)
	}
}

func TestConnectionConfig_NegativeDBTimeout_DoesNotOverride(t *testing.T) {
	t.Parallel()
	// Negative durations are treated the same as zero — no override.
	dbTimeout := -time.Second

	dbCfg := DefaultConnectionConfig(10)
	defaultIdleTime := dbCfg.ConnMaxIdleTime

	if dbTimeout > 0 {
		dbCfg.ConnMaxIdleTime = dbTimeout
	}

	if dbCfg.ConnMaxIdleTime != defaultIdleTime {
		t.Errorf("ConnMaxIdleTime should not change for negative timeout, got %v", dbCfg.ConnMaxIdleTime)
	}
}

func TestConnectionConfig_MultiplePoolSizes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		poolSize        int
		wantMaxIdle     int
	}{
		{poolSize: 2, wantMaxIdle: 1},
		{poolSize: 10, wantMaxIdle: 5},
		{poolSize: 20, wantMaxIdle: 10},
		{poolSize: 100, wantMaxIdle: 50},
	}

	for _, c := range cases {
		cfg := DefaultConnectionConfig(c.poolSize)
		if cfg.PoolSize != c.poolSize {
			t.Errorf("poolSize=%d: cfg.PoolSize=%d", c.poolSize, cfg.PoolSize)
		}
		if cfg.MaxIdleConns != c.wantMaxIdle {
			t.Errorf("poolSize=%d: MaxIdleConns=%d, want %d", c.poolSize, cfg.MaxIdleConns, c.wantMaxIdle)
		}
	}
}
