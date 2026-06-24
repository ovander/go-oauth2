package logger

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

// TestCallerHook_PointsAtRealCallSite verifies that a log emitted through this
// package's wrapper carries a "caller" pointing at the *calling* file (this
// test), not the logger package's wrapper.
func TestCallerHook_PointsAtRealCallSite(t *testing.T) {
	hook := logrustest.NewLocal(Logger)
	t.Cleanup(hook.Reset)

	Info("hello") // wrapper -> Logger.Info; the caller must resolve to THIS file

	e := hook.LastEntry()
	if e == nil {
		t.Fatal("no entry captured")
	}
	caller, ok := e.Data["caller"].(string)
	if !ok || caller == "" {
		t.Fatalf("expected a caller field, got %v", e.Data["caller"])
	}
	if strings.Contains(caller, "pkg/logger/logger.go") {
		t.Errorf("caller points at the logger wrapper, not the call site: %q", caller)
	}
	if !strings.Contains(caller, "pkg/logger/caller_test.go") {
		t.Errorf("caller should point at this test file, got %q", caller)
	}
	if strings.HasPrefix(caller, "/") {
		t.Errorf("caller should be module-relative, not an absolute path: %q", caller)
	}
}

// TestShortCaller verifies module paths become module-relative and non-module
// paths are reduced to their last two segments (never absolute).
func TestShortCaller(t *testing.T) {
	cases := map[string]string{
		modRoot + "internal/handler/oauth_handler.go": "internal/handler/oauth_handler.go",
		"/usr/lib/go/src/runtime/proc.go":             "runtime/proc.go",
		"/root/go/pkg/mod/x@v1/foo/bar/baz.go":        "bar/baz.go",
		"file.go":                                     "file.go",
	}
	for in, want := range cases {
		if got := shortCaller(in); got != want {
			t.Errorf("shortCaller(%q) = %q, want %q", in, got, want)
		}
		if strings.HasPrefix(shortCaller(in), "/") {
			t.Errorf("shortCaller(%q) leaked an absolute path: %q", in, shortCaller(in))
		}
	}
}

// TestCallerHook_PreservesExistingCaller verifies the hook does not overwrite a
// caller that an upstream (e.g. the GORM logger) already set.
func TestCallerHook_PreservesExistingCaller(t *testing.T) {
	hook := logrustest.NewLocal(Logger)
	t.Cleanup(hook.Reset)

	Logger.WithField("caller", "internal/repository/foo.go:42").Info("query")

	e := hook.LastEntry()
	if e == nil {
		t.Fatal("no entry captured")
	}
	if got := e.Data["caller"]; got != "internal/repository/foo.go:42" {
		t.Errorf("existing caller must be preserved, got %v", got)
	}
}

// TestCallerHook_DirectEntryLog verifies a direct (non-wrapper) Logger call also
// resolves to this file (the frame is outside the logger package).
func TestCallerHook_DirectEntryLog(t *testing.T) {
	hook := logrustest.NewLocal(Logger)
	t.Cleanup(hook.Reset)

	Logger.WithField("k", "v").Log(logrus.InfoLevel, "direct")

	e := hook.LastEntry()
	if e == nil || !strings.Contains(e.Data["caller"].(string), "caller_test.go") {
		t.Errorf("direct log should resolve caller to this file, got %v", e.Data["caller"])
	}
}
