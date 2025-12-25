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
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// Re-export logrus.Fields so logger.Fields works
type Fields = logrus.Fields
type Entry = logrus.Entry

var Logger *logrus.Logger

func init() {
	Logger = logrus.New()
	Logger.SetOutput(os.Stdout)
	Logger.SetReportCaller(true)

	Logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", f.File + ":" + strconv.Itoa(f.Line)
		},
	})

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
