package service

import (
	"context"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
)

// MinSeverity raises the severity derived from the event type and never
// lowers it.
func TestLog_MinSeverityRaisesButNeverLowers(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		event SecurityEvent
		want  model.SecuritySeverity
	}{
		"no floor": {SecurityEvent{EventType: model.SecurityEventClientUpdated, Success: true}, model.SecuritySeverityInfo},
		"raised": {SecurityEvent{EventType: model.SecurityEventClientUpdated, Success: true,
			MinSeverity: model.SecuritySeverityCritical}, model.SecuritySeverityCritical},
		"never lowered": {SecurityEvent{EventType: model.SecurityEventBruteForceDetected, Success: true,
			MinSeverity: model.SecuritySeverityInfo}, model.SecuritySeverityCritical},
		"unknown floor ignored": {SecurityEvent{EventType: model.SecurityEventClientDeleted, Success: true,
			MinSeverity: "bogus"}, model.SecuritySeverityWarning},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &captureAuditRepo{}
			if err := NewSecurityAuditService(repo).Log(context.Background(), tc.event); err != nil {
				t.Fatal(err)
			}
			if repo.last.Severity != tc.want {
				t.Errorf("severity %q, want %q", repo.last.Severity, tc.want)
			}
		})
	}
}
