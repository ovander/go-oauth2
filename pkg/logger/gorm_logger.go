package logger

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
	"gorm.io/gorm/utils"
)

type GormLogger struct {
	level          glogger.LogLevel
	slowThreshold  time.Duration
	ignoreNotFound bool
}

func NewGormLogger(level glogger.LogLevel, slowThreshold time.Duration, ignoreNotFound bool) glogger.Interface {
	return &GormLogger{
		level:          level,
		slowThreshold:  slowThreshold,
		ignoreNotFound: ignoreNotFound,
	}
}

func (l *GormLogger) LogMode(level glogger.LogLevel) glogger.Interface {
	l.level = level
	return l
}

func (l *GormLogger) Info(ctx context.Context, s string, args ...interface{}) {
	if l.level >= glogger.Info {
		Logger.WithContext(ctx).Infof(s, args...)
	}
}

func (l *GormLogger) Warn(ctx context.Context, s string, args ...interface{}) {
	if l.level >= glogger.Warn {
		Logger.WithContext(ctx).Warnf(s, args...)
	}
}

func (l *GormLogger) Error(ctx context.Context, s string, args ...interface{}) {
	if l.level >= glogger.Error {
		Logger.WithContext(ctx).Errorf(s, args...)
	}
}

func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if l.level == glogger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	fields := Fields{
		"duration": elapsed,
		"rows":     rows,
		"sql":      sql,
		"caller":   utils.FileWithLineNum(),
	}

	entry := Logger.WithContext(ctx).WithFields(fields)

	switch {
	case err != nil:
		// Optionally ignore not found
		if l.ignoreNotFound && errors.Is(err, gorm.ErrRecordNotFound) {
			if l.level >= glogger.Info {
				entry.Debug("🔍 SQL not found")
			}
			return
		}
		if l.level >= glogger.Error {
			entry.WithError(err).Error("💥 SQL error")
		}
	case l.slowThreshold > 0 && elapsed > l.slowThreshold:
		if l.level >= glogger.Warn {
			entry.Warn("🐢 Slow SQL query")
		}
	default:
		// Normal queries log at DEBUG, never INFO: a successful statement carries
		// bound parameters (emails, hashes, tokens, IPs) that must not land in
		// info-level logs (HIGH-06). Visible only at LOG_LEVEL=debug and when the
		// GORM level is Info.
		if l.level >= glogger.Info {
			entry.Debug("💾 SQL query")
		}
	}
}
