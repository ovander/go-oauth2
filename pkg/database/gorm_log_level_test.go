package database

import (
	"testing"

	glogger "gorm.io/gorm/logger"
)

func TestParseGormLogLevel(t *testing.T) {
	cases := map[string]glogger.LogLevel{
		"silent": glogger.Silent,
		"error":  glogger.Error,
		"warn":   glogger.Warn,
		"info":   glogger.Info,
		"INFO":   glogger.Info, // case-insensitive
		" warn ": glogger.Warn, // trimmed
		"":       glogger.Warn, // default
		"bogus":  glogger.Warn, // unknown → safe default
	}
	for in, want := range cases {
		if got := ParseGormLogLevel(in); got != want {
			t.Errorf("ParseGormLogLevel(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestDefaultConnectionConfig_QuietByDefault(t *testing.T) {
	if DefaultConnectionConfig(10).LogLevel != glogger.Warn {
		t.Error("default GORM log level should be Warn (no normal-query SQL at info)")
	}
}
