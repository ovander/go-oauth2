package web

import (
	"encoding/json"
	"net/http"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// writeJSON encodes v as JSON to w and logs any encoding error.
// See internal/handler/json.go for the full G104/G117 rationale.
func writeJSON(w http.ResponseWriter, v any) { //nolint:gosec // G117, G104
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Warnf("writeJSON: failed to encode response: %v", err)
	}
}
