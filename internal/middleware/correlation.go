package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
)

const (
	CorrelationIDHeader = "X-Correlation-ID"
	RequestIDHeader     = "X-Request-ID"
)

// CorrelationID adds a correlation ID to each request
func CorrelationID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			correlationID := r.Header.Get(CorrelationIDHeader)
			if correlationID == "" {
				correlationID = uuid.New().String()
			}

			// Set correlation ID in response header
			w.Header().Set(CorrelationIDHeader, correlationID)

			// Add to context
			ctx := context.WithValue(r.Context(), contextkeys.RequestIDKey, correlationID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetCorrelationID extracts the correlation ID from context
func GetCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(contextkeys.RequestIDKey).(string); ok {
		return id
	}
	return ""
}
