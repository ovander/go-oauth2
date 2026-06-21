package repository

import (
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

func TestVerifyAuditRows_FlagsOnlyTampered(t *testing.T) {
	t.Parallel()

	intact := sampleAuditLog()
	intact.ID = 1
	intact.RowHash = computeAuditRowHash(integritySecret, intact)

	tampered := sampleAuditLog()
	tampered.ID = 2
	tampered.RowHash = computeAuditRowHash(integritySecret, tampered)
	tampered.IPAddress = "9.9.9.9" // mutate after hashing

	noHash := sampleAuditLog()
	noHash.ID = 3 // RowHash == "" → unverifiable, skipped

	got := VerifyAuditRows(integritySecret, []model.SecurityAuditLog{*intact, *tampered, *noHash})
	if len(got) != 1 || got[0] != 2 {
		t.Errorf("VerifyAuditRows = %v, want [2]", got)
	}
}

func TestVerifyAuditRows_NilSecret(t *testing.T) {
	t.Parallel()
	l := sampleAuditLog()
	l.RowHash = "anything"
	if got := VerifyAuditRows(nil, []model.SecurityAuditLog{*l}); got != nil {
		t.Errorf("VerifyAuditRows(nil secret) = %v, want nil", got)
	}
}

func TestVerifyAuditRows_AllIntact(t *testing.T) {
	t.Parallel()
	a := sampleAuditLog()
	a.ID = 10
	a.RowHash = computeAuditRowHash(integritySecret, a)
	if got := VerifyAuditRows(integritySecret, []model.SecurityAuditLog{*a}); got != nil {
		t.Errorf("VerifyAuditRows(all intact) = %v, want nil", got)
	}
}
