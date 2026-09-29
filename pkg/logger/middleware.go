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
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/sirupsen/logrus"
)

// RequestLoggerMiddleware logs incoming HTTP requests in structured Logrus format.
//
// RFC-008: when a correlation ID is present in the request context (set by
// middleware.CorrelationID, which must run before this middleware), it is
// emitted as the "correlation_id" field so a single request can be traced
// end-to-end across log lines.
func RequestLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields := Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
		}
		// client_ip is the spoofing-resistant address resolved by
		// middleware.ClientIP (proxy headers honoured only from TRUSTED_PROXIES);
		// "remote" stays the raw TCP peer so the two can be compared in logs.
		if ip, ok := r.Context().Value(contextkeys.IPAddressKey).(string); ok && ip != "" {
			fields["client_ip"] = ip
		}
		if cid, ok := r.Context().Value(contextkeys.RequestIDKey).(string); ok && cid != "" {
			fields["correlation_id"] = cid
		}
		entry := Logger.WithFields(fields)

		t0 := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		entry.Debug("📥 Incoming request")

		next.ServeHTTP(ww, r)

		duration := time.Since(t0)
		// Level by outcome so error rates are queryable/alertable by level:
		// 5xx → Error, 4xx → Warn, else Info.
		entry.WithFields(Fields{
			"status":   ww.Status(),
			"bytes":    ww.BytesWritten(),
			"duration": duration,
		}).Log(levelForStatus(ww.Status()), "📤 Request handled")
	})
}

// levelForStatus maps an HTTP status code to a log level: 5xx → Error, 4xx →
// Warn, otherwise Info.
func levelForStatus(status int) logrus.Level {
	switch {
	case status >= 500:
		return logrus.ErrorLevel
	case status >= 400:
		return logrus.WarnLevel
	default:
		return logrus.InfoLevel
	}
}
