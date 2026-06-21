// Package repository — tests for RFC-007 audit hash-chaining (deletion /
// reordering detection), complementing the per-row mutation tests.
package repository

import (
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// buildChainedRows returns n rows correctly hash-chained with the given secret,
// IDs 1..n, each row's PrevHash linking to the previous row's RowHash.
func buildChainedRows(secret []byte, n int) []model.SecurityAuditLog {
	rows := make([]model.SecurityAuditLog, n)
	prev := ""
	base := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		uid := uint(i + 1)
		rows[i] = model.SecurityAuditLog{
			ID:        uint(i + 1),
			UserID:    &uid,
			EventType: model.SecurityEventLoginSuccess,
			Severity:  model.SecuritySeverityInfo,
			IPAddress: "1.2.3.4",
			Success:   true,
			Details:   map[string]interface{}{"seq": i},
			CreatedAt: base.Add(time.Duration(i) * time.Second),
			PrevHash:  prev,
		}
		rows[i].RowHash = computeAuditRowHash(secret, &rows[i])
		prev = rows[i].RowHash
	}
	return rows
}

func TestVerifyAuditChain_IntactChain(t *testing.T) {
	rows := buildChainedRows(integritySecret, 5)
	if broken := VerifyAuditChain(integritySecret, rows); broken != nil {
		t.Fatalf("expected no breaks for an intact chain, got %v", broken)
	}
}

func TestVerifyAuditChain_OrderIndependent(t *testing.T) {
	rows := buildChainedRows(integritySecret, 4)
	// Shuffle the input order; the verifier must sort by ID internally.
	rows[0], rows[3] = rows[3], rows[0]
	if broken := VerifyAuditChain(integritySecret, rows); broken != nil {
		t.Fatalf("expected no breaks regardless of input order, got %v", broken)
	}
}

func TestVerifyAuditChain_DetectsDeletion(t *testing.T) {
	rows := buildChainedRows(integritySecret, 5)
	// Delete the middle row (id 3); the row after the gap (id 4) now links to a
	// hash that is no longer present immediately before it.
	withoutMiddle := []model.SecurityAuditLog{rows[0], rows[1], rows[3], rows[4]}
	broken := VerifyAuditChain(integritySecret, withoutMiddle)
	if len(broken) != 1 || broken[0] != 4 {
		t.Fatalf("expected row 4 flagged after deleting row 3, got %v", broken)
	}
}

func TestVerifyAuditChain_DetectsReorder(t *testing.T) {
	rows := buildChainedRows(integritySecret, 4)
	// Swap the IDs of two adjacent rows to simulate reordering (their PrevHash
	// values no longer line up with the new sequence).
	rows[1].ID, rows[2].ID = rows[2].ID, rows[1].ID
	broken := VerifyAuditChain(integritySecret, rows)
	if len(broken) == 0 {
		t.Fatal("expected reordering to break the chain")
	}
}

func TestVerifyAuditChain_PureMutationDoesNotBreakChain(t *testing.T) {
	// A content mutation (without recomputing RowHash, which an attacker without
	// the secret cannot do) leaves the stored RowHash — and therefore the chain
	// links — intact. Mutation is caught by VerifyAuditRows, not the chain check.
	rows := buildChainedRows(integritySecret, 3)
	rows[1].IPAddress = "9.9.9.9" // tampered content, RowHash left as-is
	if broken := VerifyAuditChain(integritySecret, rows); broken != nil {
		t.Fatalf("chain link check should be unaffected by in-place mutation, got %v", broken)
	}
	// ...but the mutation IS detectable by the per-row HMAC check.
	if tampered := VerifyAuditRows(integritySecret, rows); len(tampered) != 1 || tampered[0] != 2 {
		t.Fatalf("expected mutation of row 2 detected by VerifyAuditRows, got %v", tampered)
	}
}

func TestVerifyAuditChain_SkipsUnstampedRows(t *testing.T) {
	rows := buildChainedRows(integritySecret, 3)
	// A pre-integrity row (no RowHash) must not participate or break the chain.
	rows = append(rows, model.SecurityAuditLog{ID: 99, EventType: model.SecurityEventLogout})
	if broken := VerifyAuditChain(integritySecret, rows); broken != nil {
		t.Fatalf("unstamped rows must be skipped, got %v", broken)
	}
}

func TestVerifyAuditChain_EmptySecret(t *testing.T) {
	rows := buildChainedRows(integritySecret, 3)
	if broken := VerifyAuditChain(nil, rows); broken != nil {
		t.Fatalf("expected nil for an empty secret, got %v", broken)
	}
}

func TestPrevHash_BindsRowHash(t *testing.T) {
	// The same row content yields a different hash once it is chained, proving
	// PrevHash is bound into the row hash.
	log := sampleAuditLog()
	bare := computeAuditRowHash(integritySecret, log)
	log.PrevHash = "deadbeef"
	chained := computeAuditRowHash(integritySecret, log)
	if bare == chained {
		t.Fatal("expected PrevHash to change the computed row hash")
	}
}

func TestPrevHash_EmptyIsBackwardCompatible(t *testing.T) {
	// A row with an empty PrevHash must hash and verify exactly as before
	// chaining (omitempty keeps the canonical payload identical), so existing
	// stamped rows remain verifiable.
	log := sampleAuditLog()
	log.PrevHash = ""
	log.RowHash = computeAuditRowHash(integritySecret, log)
	if !VerifyAuditRowHash(integritySecret, log) {
		t.Fatal("a row with empty PrevHash must still verify")
	}
}
