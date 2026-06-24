package logger

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	glogger "gorm.io/gorm/logger"
)

// traceNormal drives a successful (non-slow, non-error) query through the GORM
// logger at the given GORM level and returns the captured logrus entries while
// the logrus Logger is pinned at the given logrus level.
func traceNormal(t *testing.T, gormLevel glogger.LogLevel, logrusLevel logrus.Level) []*logrus.Entry {
	t.Helper()
	hook := logrustest.NewLocal(Logger)
	t.Cleanup(hook.Reset)
	prev := Logger.GetLevel()
	Logger.SetLevel(logrusLevel)
	t.Cleanup(func() { Logger.SetLevel(prev) })

	gl := NewGormLogger(gormLevel, 200*time.Millisecond, true)
	begin := time.Now().Add(-time.Millisecond) // fast query (not slow)
	gl.Trace(context.Background(), begin, func() (string, int64) {
		return "SELECT * FROM users WHERE email = 'secret@example.com'", 1
	}, nil)
	return hook.AllEntries()
}

func TestGormLogger_NormalQuery_NotLoggedAtInfo(t *testing.T) {
	// Even when GORM is set to Info (log everything), a normal query must not be
	// visible at logrus info — it logs at debug. This is the HIGH-06 guard:
	// bound parameters never appear in info-level logs.
	if entries := traceNormal(t, glogger.Info, logrus.InfoLevel); len(entries) != 0 {
		t.Errorf("normal query must not log at info, got %d entries: %q", len(entries), entries[0].Message)
	}
}

func TestGormLogger_NormalQuery_VisibleAtDebug(t *testing.T) {
	entries := traceNormal(t, glogger.Info, logrus.DebugLevel)
	if len(entries) != 1 || entries[0].Level != logrus.DebugLevel {
		t.Fatalf("normal query should log once at debug when GORM=Info and LOG_LEVEL=debug, got %d", len(entries))
	}
}

func TestGormLogger_WarnLevel_SkipsNormalQuery(t *testing.T) {
	// At the default GORM level (Warn) a normal query is not rendered or logged
	// even with logrus at debug.
	if entries := traceNormal(t, glogger.Warn, logrus.DebugLevel); len(entries) != 0 {
		t.Errorf("GORM Warn level must skip normal queries entirely, got %d", len(entries))
	}
}

func TestGormLogger_Error_LoggedAtError(t *testing.T) {
	hook := logrustest.NewLocal(Logger)
	t.Cleanup(hook.Reset)
	gl := NewGormLogger(glogger.Error, 200*time.Millisecond, true)
	gl.Trace(context.Background(), time.Now(), func() (string, int64) { return "SELECT 1", 0 }, errors.New("boom"))
	if e := hook.LastEntry(); e == nil || e.Level != logrus.ErrorLevel {
		t.Errorf("a query error should log at error level")
	}
}

func TestGormLogger_LevelGatesNormalQuery(t *testing.T) {
	cases := map[glogger.LogLevel]bool{ // gormLevel -> normal query rendered (at debug)
		glogger.Silent: false,
		glogger.Error:  false,
		glogger.Warn:   false,
		glogger.Info:   true,
	}
	for lvl, wantLogged := range cases {
		got := len(traceNormal(t, lvl, logrus.DebugLevel)) > 0
		if got != wantLogged {
			t.Errorf("gorm level %d: normal-query logged=%v, want %v", lvl, got, wantLogged)
		}
	}
}
