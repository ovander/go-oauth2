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

// WithReadTimeout adds a read timeout to the context.
// The caller is responsible for calling the returned CancelFunc.
func WithReadTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DefaultReadTimeout) //nolint:govet // G118 false positive: wrapper; CancelFunc returned to caller
}

// WithWriteTimeout adds a write timeout to the context.
// The caller is responsible for calling the returned CancelFunc.
func WithWriteTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DefaultWriteTimeout) //nolint:govet // G118 false positive: wrapper; CancelFunc returned to caller
}

// WithLongTimeout adds a longer timeout for complex operations.
// The caller is responsible for calling the returned CancelFunc.
func WithLongTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DefaultLongTimeout) //nolint:govet // G118 false positive: wrapper; CancelFunc returned to caller
}

// WithTimeout adds a custom timeout to the context.
// The caller is responsible for calling the returned CancelFunc.
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout) //nolint:govet // G118 false positive: wrapper; CancelFunc returned to caller
}

// EnsureTimeout returns a context with a timeout if one isn't already set.
// This is useful for wrapping incoming contexts that may or may not have timeouts.
// The caller is responsible for calling the returned CancelFunc.
func EnsureTimeout(ctx context.Context, defaultTimeout time.Duration) (context.Context, context.CancelFunc) {
	// Check if context already has a deadline
	if _, ok := ctx.Deadline(); ok {
		// Context already has a deadline, use a no-op cancel function
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultTimeout) //nolint:govet // G118 false positive: wrapper; CancelFunc returned to caller
}
