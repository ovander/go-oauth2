/*
 * // Copyright (c) 2023–2025 Olivier Vandermoten
 * //
 * // This file is part of the DTMA (Digital Transformation Maturity Assessment) software.
 * //
 * // DTMA is proprietary software: you may not use, copy, modify, or distribute this
 * // file except in compliance with the license agreement provided separately.
 * //
 * // For licensing inquiries, contact: olivier.vandermoten@gmail.com
 */

package logger

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/sirupsen/logrus"
)

// Re-export logrus.Fields so logger.Fields works
type Fields = logrus.Fields
type Entry = logrus.Entry

var Logger *logrus.Logger

// FromContext returns a log entry pre-populated with request-scoped fields from
// ctx — currently the correlation_id (RFC-008) when present — so service-layer
// logs can be traced to a single request end-to-end, the same way the request
// logger and the audit log already are. Safe with a nil context.
//
// Usage: logger.FromContext(ctx).WithError(err).Error("...") or
// logger.FromContext(ctx).Warnf("...", a).
func FromContext(ctx context.Context) *logrus.Entry {
	if ctx != nil {
		if cid, ok := ctx.Value(contextkeys.RequestIDKey).(string); ok && cid != "" {
			return Logger.WithField("correlation_id", cid)
		}
	}
	return logrus.NewEntry(Logger)
}

// selectFormatter chooses the log output format. An explicit LOG_FORMAT
// (json|text) wins; otherwise it derives from the environment — structured
// **JSON in production** (clean ingestion by ELK/Loki/Datadog) and
// human-readable **text in development/test**. ENV unset is treated as
// production (matching config's fail-safe default).
func selectFormatter(logFormat, env string) logrus.Formatter {
	caller := func(f *runtime.Frame) (string, string) {
		return "", f.File + ":" + strconv.Itoa(f.Line)
	}
	useJSON := true
	switch strings.ToLower(strings.TrimSpace(logFormat)) {
	case "json":
		useJSON = true
	case "text":
		useJSON = false
	default:
		switch strings.ToLower(strings.TrimSpace(env)) {
		case "development", "dev", "test", "local":
			useJSON = false
		}
	}
	if useJSON {
		return &logrus.JSONFormatter{
			TimestampFormat:  "2006-01-02T15:04:05.000Z07:00",
			CallerPrettyfier: caller,
		}
	}
	return &logrus.TextFormatter{
		FullTimestamp:    true,
		TimestampFormat:  "2006-01-02 15:04:05",
		CallerPrettyfier: caller,
	}
}

func init() {
	Logger = logrus.New()
	Logger.SetOutput(os.Stdout)
	Logger.SetReportCaller(true)

	Logger.SetFormatter(selectFormatter(os.Getenv("LOG_FORMAT"), os.Getenv("ENV")))

	levelStr := strings.ToLower(os.Getenv("LOG_LEVEL"))

	var level logrus.Level
	var err error

	if levelStr == "" {
		level = logrus.InfoLevel
	} else {
		level, err = logrus.ParseLevel(levelStr)
		if err != nil {
			Logger.Warnf("⚠️ Invalid log level '%s', defaulting to 'info'", levelStr)
			level = logrus.InfoLevel
		}
	}
	Logger.SetLevel(level)
	Logger.Infof("✅ Logger initialized with level: %s", level.String())
}

func WithError(err error) *logrus.Entry {
	return Logger.WithError(err)
}

// Convenient wrappers
func Debug(args ...interface{})                 { Logger.Debug(args...) }
func Debugf(format string, args ...interface{}) { Logger.Debugf(format, args...) }

func Info(args ...interface{})                 { Logger.Info(args...) }
func Infof(format string, args ...interface{}) { Logger.Infof(format, args...) }

func Warn(args ...interface{})                 { Logger.Warn(args...) }
func Warnf(format string, args ...interface{}) { Logger.Warnf(format, args...) }

func Error(args ...interface{})                 { Logger.Error(args...) }
func Errorf(format string, args ...interface{}) { Logger.Errorf(format, args...) }

func Fatal(args ...interface{})                 { Logger.Fatal(args...) }
func Fatalf(format string, args ...interface{}) { Logger.Fatalf(format, args...) }

func Panic(args ...interface{})                 { Logger.Panic(args...) }
func Panicf(format string, args ...interface{}) { Logger.Panicf(format, args...) }

func WithField(key string, value interface{}) *logrus.Entry {
	return Logger.WithField(key, value)
}

func WithFields(fields logrus.Fields) *logrus.Entry {
	return Logger.WithFields(fields)
}
