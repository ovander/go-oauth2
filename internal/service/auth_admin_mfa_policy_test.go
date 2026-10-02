package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
)

// TestEnforceAdminMFAPolicy covers the admin MFA-enrollment policy matrix:
// (off|observe|enforce) × (enrolled|not enrolled).
func TestEnforceAdminMFAPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		enrolled bool
		wantErr  error
	}{
		{"off + not enrolled -> allow", MFAPolicyOff, false, nil},
		{"off + enrolled -> allow", MFAPolicyOff, true, nil},
		{"unset + not enrolled -> allow", "", false, nil},
		{"observe + not enrolled -> allow (audited)", MFAPolicyObserve, false, nil},
		{"observe + enrolled -> allow", MFAPolicyObserve, true, nil},
		{"enforce + not enrolled -> deny", MFAPolicyEnforce, false, ErrMFAEnrollmentRequired},
		{"enforce + enrolled -> allow", MFAPolicyEnforce, true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &authService{adminMFAPolicy: tc.policy}
			user := &model.User{ID: 1, Email: "admin@example.com", MFAEnabled: tc.enrolled}
			err := s.enforceAdminMFAPolicy(context.Background(), user, "password")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("policy=%q enrolled=%v: got %v, want %v", tc.policy, tc.enrolled, err, tc.wantErr)
			}
		})
	}
}
