package logger

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

func TestSelectFormatter(t *testing.T) {
	cases := []struct {
		logFormat, env string
		wantJSON       bool
	}{
		{"json", "development", true}, // explicit wins
		{"text", "production", false}, // explicit wins
		{"", "production", true},      // env-derived
		{"", "", true},                // unset env => production => json
		{"", "development", false},    // dev => text
		{"", "test", false},           // test => text
		{"WeIrD", "production", true}, // unknown format => env-derived
	}
	for _, c := range cases {
		f := selectFormatter(c.logFormat, c.env)
		_, isJSON := f.(*logrus.JSONFormatter)
		if isJSON != c.wantJSON {
			t.Errorf("selectFormatter(%q,%q) json=%v, want %v", c.logFormat, c.env, isJSON, c.wantJSON)
		}
	}
}

func TestLevelForStatus(t *testing.T) {
	cases := map[int]logrus.Level{
		200: logrus.InfoLevel, 302: logrus.InfoLevel,
		400: logrus.WarnLevel, 404: logrus.WarnLevel, 429: logrus.WarnLevel,
		500: logrus.ErrorLevel, 503: logrus.ErrorLevel,
	}
	for status, want := range cases {
		if got := levelForStatus(status); got != want {
			t.Errorf("levelForStatus(%d) = %v, want %v", status, got, want)
		}
	}
}

// The request logger emits at the level matching the response status.
func TestRequestLogger_LevelByOutcome(t *testing.T) {
	hook := logrustest.NewLocal(Logger)
	t.Cleanup(hook.Reset)
	prev := Logger.GetLevel()
	Logger.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() { Logger.SetLevel(prev) })

	for _, tc := range []struct {
		status int
		want   logrus.Level
	}{{200, logrus.InfoLevel}, {404, logrus.WarnLevel}, {500, logrus.ErrorLevel}} {
		hook.Reset()
		h := RequestLoggerMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

		var handled *logrus.Entry
		for _, e := range hook.AllEntries() {
			if e.Message == "📤 Request handled" {
				handled = e
			}
		}
		if handled == nil {
			t.Fatalf("status %d: no 'Request handled' entry", tc.status)
		}
		if handled.Level != tc.want {
			t.Errorf("status %d logged at %v, want %v", tc.status, handled.Level, tc.want)
		}
	}
}
