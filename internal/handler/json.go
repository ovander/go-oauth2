package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// writeJSON encodes v as JSON to w and logs any encoding error.
//
// gosec G104 rationale: by the time json.Encoder.Encode can fail on an
// http.ResponseWriter, the response status line and headers have already been
// flushed. There is no way for the handler to change the status code, and
// retrying or propagating the error cannot improve the client's experience.
// The error is therefore logged for observability but not returned.
//
// gosec G117 rationale: this helper is intentionally used to deliver
// access_token, refresh_token, and client_secret fields as mandated by
// RFC 6749, RFC 7009, RFC 7662, and the OAuth 2.0 token endpoint contract.
// Those fields must appear in the JSON response body.
func writeJSON(w http.ResponseWriter, v any) { //nolint:gosec // G117, G104: see above
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Warnf("writeJSON: failed to encode response: %v", err)
	}
}
