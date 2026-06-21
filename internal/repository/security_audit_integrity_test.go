// Package repository — tests for RFC-007 per-row audit integrity HMAC.
package repository

import (
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

var integritySecret = []byte("test-secret-key-base-at-least-32-bytes-long!!")

func sampleAuditLog() *model.SecurityAuditLog {
	uid := uint(42)
	aid := uint(7)
	return &model.SecurityAuditLog{
		UserID:        &uid,
		AppID:         &aid,
		EventType:     model.SecurityEventLoginFailed,
		Severity:      model.SecuritySeverityWarning,
		IPAddress:     "1.2.3.4",
		UserAgent:     "agent/1.0",
		CorrelationID: "corr-1",
		Success:       false,
		Details:       map[string]interface{}{"reason": "bad_password", "attempt": 3},
		CreatedAt:     time.Date(2026, 6, 21, 12, 0, 0, 123456000, time.UTC),
	}
}

func TestComputeAuditRowHash_Deterministic(t *testing.T) {
	t.Parallel()
	h1 := computeAuditRowHash(integritySecret, sampleAuditLog())
	h2 := computeAuditRowHash(integritySecret, sampleAuditLog())
	if h1 == "" || h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64 (hex sha256)", len(h1))
	}
}

func TestComputeAuditRowHash_DisabledWhenNoSecret(t *testing.T) {
	t.Parallel()
	if h := computeAuditRowHash(nil, sampleAuditLog()); h != "" {
		t.Errorf("hash with nil secret = %q, want empty", h)
	}
}

func TestVerifyAuditRowHash_IntactRow(t *testing.T) {
	t.Parallel()
	log := sampleAuditLog()
	log.RowHash = computeAuditRowHash(integritySecret, log)
	if !VerifyAuditRowHash(integritySecret, log) {
		t.Error("expected intact row to verify")
	}
}

func TestVerifyAuditRowHash_DetectsTampering(t *testing.T) {
	t.Parallel()
	base := sampleAuditLog()
	base.RowHash = computeAuditRowHash(integritySecret, base)

	mutate := map[string]func(*model.SecurityAuditLog){
		"event_type":     func(l *model.SecurityAuditLog) { l.EventType = model.SecurityEventLoginSuccess },
		"severity":       func(l *model.SecurityAuditLog) { l.Severity = model.SecuritySeverityInfo },
		"ip_address":     func(l *model.SecurityAuditLog) { l.IPAddress = "9.9.9.9" },
		"correlation_id": func(l *model.SecurityAuditLog) { l.CorrelationID = "other" },
		"success":        func(l *model.SecurityAuditLog) { l.Success = true },
		"details":        func(l *model.SecurityAuditLog) { l.Details = map[string]interface{}{"reason": "ok"} },
		"created_at":     func(l *model.SecurityAuditLog) { l.CreatedAt = l.CreatedAt.Add(time.Second) },
	}
	for field, mut := range mutate {
		tampered := sampleAuditLog()
		tampered.RowHash = base.RowHash // keep the original hash
		mut(tampered)
		if VerifyAuditRowHash(integritySecret, tampered) {
			t.Errorf("tampering with %q was not detected", field)
		}
	}
}

func TestVerifyAuditRowHash_FalseWhenNoSecretOrNoHash(t *testing.T) {
	t.Parallel()
	log := sampleAuditLog()
	log.RowHash = computeAuditRowHash(integritySecret, log)

	if VerifyAuditRowHash(nil, log) {
		t.Error("verify with nil secret should be false")
	}
	noHash := sampleAuditLog() // RowHash == ""
	if VerifyAuditRowHash(integritySecret, noHash) {
		t.Error("verify with empty RowHash should be false")
	}
}

// Simulates a DB round trip: jsonb coerces integers to float64 and the
// timestamp is already microsecond precision. Verification must still pass.
func TestVerifyAuditRowHash_StableAcrossDBRoundTrip(t *testing.T) {
	t.Parallel()
	written := sampleAuditLog()
	// As written by Create: timestamp reduced to micros.
	written.CreatedAt = written.CreatedAt.UTC().Truncate(time.Microsecond)
	written.RowHash = computeAuditRowHash(integritySecret, written)

	// As read back from Postgres: Details numbers come back as float64, key
	// order may differ; CreatedAt round-trips at microsecond precision.
	readBack := *written
	readBack.Details = map[string]interface{}{"attempt": float64(3), "reason": "bad_password"}

	if !VerifyAuditRowHash(integritySecret, &readBack) {
		t.Error("verification should be stable across a simulated DB round trip")
	}
}

func TestCanonicalJSON_NilIsNull(t *testing.T) {
	t.Parallel()
	if got := string(canonicalJSON(nil)); got != "null" {
		t.Errorf("canonicalJSON(nil) = %q, want null", got)
	}
}
