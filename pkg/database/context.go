package database

import (
	"context"
	"time"
)

// Default database operation timeouts
const (
	DefaultReadTimeout  = 5 * time.Second
	DefaultWriteTimeout = 10 * time.Second
	DefaultLongTimeout  = 30 * time.Second
)

// WithReadTimeout adds a read timeout to the context
func WithReadTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DefaultReadTimeout)
}

// WithWriteTimeout adds a write timeout to the context
func WithWriteTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DefaultWriteTimeout)
}

// WithLongTimeout adds a longer timeout for complex operations
func WithLongTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DefaultLongTimeout)
}

// WithTimeout adds a custom timeout to the context
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// EnsureTimeout returns a context with a timeout if one isn't already set.
// This is useful for wrapping incoming contexts that may or may not have timeouts.
func EnsureTimeout(ctx context.Context, defaultTimeout time.Duration) (context.Context, context.CancelFunc) {
	// Check if context already has a deadline
	if _, ok := ctx.Deadline(); ok {
		// Context already has a deadline, use a no-op cancel function
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultTimeout)
}
