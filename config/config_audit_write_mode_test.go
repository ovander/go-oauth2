package config

import "testing"

func TestConfig_AuditWriteMode(t *testing.T) {
	for in, want := range map[string]string{"": "sync", "sync": "sync", " ASYNC ": "async", "asynchronous": "sync"} {
		t.Setenv("AUDIT_WRITE_MODE", in)
		if got := Load().AuditWriteMode; got != want {
			t.Errorf("AUDIT_WRITE_MODE=%q -> %q, want %q", in, got, want)
		}
	}
}
