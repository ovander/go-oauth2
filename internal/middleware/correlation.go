package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/ovander/go-oauth2/internal/contextkeys"
)

const (
	CorrelationIDHeader = "X-Correlation-ID"
	RequestIDHeader     = "X-Request-ID"
)

// MaxCorrelationIDLength is the longest incoming correlation ID that is kept.
const MaxCorrelationIDLength = 128

// CorrelationID adds a correlation ID to each request. An incoming
// X-Correlation-ID is kept only when ValidCorrelationID accepts it; otherwise,
// or when the header is absent, a new UUID is generated. The request is never
// rejected. The ID is echoed in the response and stored in the context, from
// where it reaches logs and audit fields, so a caller cannot inject line
// breaks, control characters or unbounded text through it.
func CorrelationID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			correlationID := r.Header.Get(CorrelationIDHeader)
			if !ValidCorrelationID(correlationID) {
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

// ValidCorrelationID reports whether id is acceptable as a correlation ID: 1 to
// MaxCorrelationIDLength characters of A-Z, a-z, 0-9, '.', '_', ':' and '-' (UUIDs,
// ULIDs and similar). It is the same rule as backendkit's httpware.RequestID.
func ValidCorrelationID(id string) bool {
	if id == "" || len(id) > MaxCorrelationIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		switch c := id[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}
