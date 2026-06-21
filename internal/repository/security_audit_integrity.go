package repository

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// Audit-log tamper evidence (RFC-007).
//
// computeAuditRowHash stamps a keyed HMAC-SHA256 over each audit row's
// immutable content at write time; VerifyAuditRowHash recomputes and compares
// it. Because the secret (SECRET_KEY_BASE) lives in application configuration
// and never in the database, a row mutated by anyone with database-only access
// — but without the secret — fails verification and is therefore detectable.
//
// Scope/limitation: this detects row *mutation*. It does not detect row
// deletion or insertion; that requires hash-chaining (a separate RFC-007
// slice).

// computeAuditRowHash returns the hex-encoded HMAC-SHA256 over a canonical,
// DB-round-trip-stable serialization of the row's immutable fields. It returns
// "" when secret is empty (integrity disabled). RowHash itself is never part of
// the payload, so there is no self-reference.
func computeAuditRowHash(secret []byte, log *model.SecurityAuditLog) string {
	if len(secret) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(canonicalAuditPayload(log))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAuditRowHash recomputes the row hash and compares it (constant-time)
// against the stored RowHash. It returns true only when integrity is intact.
// When the secret is empty or the row carries no stored hash, it returns false
// (the row cannot be verified).
func VerifyAuditRowHash(secret []byte, log *model.SecurityAuditLog) bool {
	if len(secret) == 0 || log.RowHash == "" {
		return false
	}
	expected := computeAuditRowHash(secret, log)
	return hmac.Equal([]byte(expected), []byte(log.RowHash))
}

// canonicalAuditPayload builds a deterministic, DB-round-trip-stable byte
// representation of the immutable audit fields. CreatedAt is reduced to
// microseconds (PostgreSQL timestamptz precision) and Details is normalized
// through a JSON round-trip so that integer/float coercion and key ordering
// introduced by jsonb storage do not alter the hash.
func canonicalAuditPayload(log *model.SecurityAuditLog) []byte {
	c := struct {
		UserID             *uint           `json:"user_id"`
		AppID              *uint           `json:"app_id"`
		EventType          string          `json:"event_type"`
		Severity           string          `json:"severity"`
		IPAddress          string          `json:"ip_address"`
		UserAgent          string          `json:"user_agent"`
		CorrelationID      string          `json:"correlation_id"`
		Success            bool            `json:"success"`
		Details            json.RawMessage `json:"details"`
		CreatedAtUnixMicro int64           `json:"created_at_unix_micro"`
	}{
		UserID:             log.UserID,
		AppID:              log.AppID,
		EventType:          string(log.EventType),
		Severity:           string(log.Severity),
		IPAddress:          log.IPAddress,
		UserAgent:          log.UserAgent,
		CorrelationID:      log.CorrelationID,
		Success:            log.Success,
		Details:            canonicalJSON(log.Details),
		CreatedAtUnixMicro: log.CreatedAt.UTC().Truncate(time.Microsecond).UnixMicro(),
	}
	// A struct marshals with fields in declaration order; map keys inside
	// Details are already normalized/sorted by canonicalJSON.
	b, _ := json.Marshal(c)
	return b
}

// canonicalJSON normalizes an arbitrary value through a JSON round-trip so the
// result matches what reading the value back from a jsonb column would produce
// (numbers as float64, map keys sorted by encoding/json). It returns the JSON
// literal "null" for nil or unmarshalable input.
func canonicalJSON(v interface{}) json.RawMessage {
	if v == nil {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	var normalized interface{}
	if err := json.Unmarshal(b, &normalized); err != nil {
		return json.RawMessage(b)
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return json.RawMessage(b)
	}
	return json.RawMessage(out)
}
