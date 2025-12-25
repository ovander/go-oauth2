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
)

// RequestLoggerMiddleware logs incoming HTTP requests in structured Logrus format
func RequestLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry := Logger.WithFields(Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
		})

		t0 := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		entry.Debug("📥 Incoming request")

		next.ServeHTTP(ww, r)

		duration := time.Since(t0)
		entry.WithFields(Fields{
			"status":   ww.Status(),
			"bytes":    ww.BytesWritten(),
			"duration": duration,
		}).Info("📤 Request handled")
	})
}
