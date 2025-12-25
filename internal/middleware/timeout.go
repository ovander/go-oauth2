package middleware

import (
	"context"
	"net/http"
	"time"
)

// RequestTimeoutConfig holds configuration for request timeouts
type RequestTimeoutConfig struct {
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DefaultRequestTimeoutConfig returns sensible defaults
func DefaultRequestTimeoutConfig() RequestTimeoutConfig {
	return RequestTimeoutConfig{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}

// RequestTimeout middleware adds a timeout to the request context
// This ensures that database operations and other async tasks don't hang indefinitely
func RequestTimeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			// Replace request with one that has the timeout context
			r = r.WithContext(ctx)

			// Create a channel to track completion
			done := make(chan struct{})

			go func() {
				next.ServeHTTP(w, r)
				close(done)
			}()

			select {
			case <-done:
				// Request completed normally
				return
			case <-ctx.Done():
				// Context timed out or was cancelled
				if ctx.Err() == context.DeadlineExceeded {
					http.Error(w, "Request timeout", http.StatusGatewayTimeout)
				}
				return
			}
		})
	}
}

// RequestTimeoutSimple adds a timeout to the request context without the goroutine wrapper
// Use this for simpler timeout handling where you trust the handler to respect context cancellation
func RequestTimeoutSimple(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
