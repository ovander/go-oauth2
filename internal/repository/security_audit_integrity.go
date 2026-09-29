package repository

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// Audit-log tamper evidence (RFC-007).
//
// computeAuditRowHash stamps a keyed HMAC-SHA256 over each audit row's
// immutable content at write time; VerifyAuditRowHash recomputes and compares
// it. Because the secret (SECRET_KEY_BASE) lives in application configuration
// and never in the database, a row mutated by anyone with database-only access
// — but without the secret — fails verification and is therefore detectable.
//
// Each row also carries the previous chained row's hash (PrevHash), forming a
// hash chain. VerifyAuditChain walks an ordered range and reports any row whose
// backward link is broken — which is what a deletion, insertion, or reordering
// of rows produces — extending detection beyond in-place mutation.

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

// VerifyAuditRows returns the IDs of the rows that carry a RowHash but fail
// verification (i.e. were tampered with). Rows with an empty RowHash are skipped
// — they predate integrity stamping and cannot be verified. Returns nil for an
// empty secret.
func VerifyAuditRows(secret []byte, logs []model.SecurityAuditLog) []uint {
	if len(secret) == 0 {
		return nil
	}
	var tampered []uint
	for i := range logs {
		if logs[i].RowHash == "" {
			continue // unverifiable (pre-integrity row)
		}
		if !VerifyAuditRowHash(secret, &logs[i]) {
			tampered = append(tampered, logs[i].ID)
		}
	}
	return tampered
}

// VerifyAuditChain checks the hash chain over a slice of audit rows and returns
// the IDs of rows whose backward link is broken — i.e. a row that carries a
// PrevHash which does not equal the RowHash of the immediately preceding chained
// row in the slice. A break is what deletion, insertion, or reordering of rows
// produces.
//
// The slice is sorted by ID ascending first (callers may pass any order). Only
// rows that carry a RowHash participate; rows with an empty RowHash (written
// before integrity stamping) are skipped and do not break the chain. The first
// participating row is the anchor and is not link-checked, since its
// predecessor may lie outside the provided range. Returns nil for an empty
// secret. VerifyAuditChain checks links only; pair it with VerifyAuditRows to
// also catch in-place mutation.
func VerifyAuditChain(secret []byte, logs []model.SecurityAuditLog) []uint {
	if len(secret) == 0 {
		return nil
	}
	// Sort a copy by ID ascending so the caller's ordering does not matter.
	ordered := make([]model.SecurityAuditLog, len(logs))
	copy(ordered, logs)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	var broken []uint
	var prev *model.SecurityAuditLog
	for i := range ordered {
		row := &ordered[i]
		if row.RowHash == "" {
			continue // unchained (pre-integrity) row
		}
		if prev != nil && row.PrevHash != prev.RowHash {
			broken = append(broken, row.ID)
		}
		prev = row
	}
	return broken
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
		// PrevHash chains the row to its predecessor. It is omitempty so rows
		// written before chaining (PrevHash == "") hash identically to the
		// pre-chaining format and remain verifiable.
		PrevHash string `json:"prev_hash,omitempty"`
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
		PrevHash:           log.PrevHash,
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
