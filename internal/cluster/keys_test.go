package cluster

import "testing"

// Two jobs sharing a lock key would serialise each other at best, and at worst
// one would never run on any instance. The keys are hand-assigned constants,
// so check they stay distinct as new ones are added.
func TestLockKeys_AreDistinct(t *testing.T) {
	keys := map[string]int64{
		"LockMigrations":          LockMigrations,
		"LockKeyRotation":         LockKeyRotation,
		"LockUsedTokenSweep":      LockUsedTokenSweep,
		"LockAuditScan":           LockAuditScan,
		"LockStateSweep":          LockStateSweep,
		"LockPolicyDecisionSweep": LockPolicyDecisionSweep,
	}
	seen := map[int64]string{}
	for name, k := range keys {
		if other, dup := seen[k]; dup {
			t.Errorf("%s and %s share lock key %#x", name, other, k)
		}
		seen[k] = name
	}
}
