// Package service — regression guard for L1 (Socrate suite audit): a
// user-enumeration timing side channel on login.
//
// Before the fix, Login/AdminLogin looked the email up first and returned
// ErrInvalidCredentials immediately on a miss — skipping the bcrypt
// CheckPassword call entirely. A known email with a wrong password always
// pays the bcrypt cost (tens of milliseconds), so an unknown email returned
// measurably faster, letting an attacker enumerate registered accounts by
// timing. The fix pays a dummy bcrypt comparison (auth.CheckDummyPassword) on
// the not-found path so both cases cost about the same.
package service

import (
	"context"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// timingRatioWithinTolerance reports whether a/b falls within [0.3, 3.0] — a
// generous band chosen to absorb scheduler/GC noise on a shared CI runner
// while still catching a regression to the old cheap short-circuit (which
// would produce a much more extreme ratio, typically >10x).
func timingRatioWithinTolerance(a, b time.Duration) bool {
	if a <= 0 || b <= 0 {
		return false
	}
	ratio := float64(a) / float64(b)
	return ratio >= 0.3 && ratio <= 3.0
}

// TestLogin_UnknownEmail_TimingParityWithWrongPassword is the L1 regression
// guard for the interactive/app login path.
func TestLogin_UnknownEmail_TimingParityWithWrongPassword(t *testing.T) {
	pw := "Str0ng!Passw0rd"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user := &model.User{
		ID: 1, Email: "real-user@example.com", HashedPassword: hash,
		IsVerified: true, Role: model.UserRoleUser,
	}
	svc := newLoginSvc(t, user)

	const iterations = 5
	var knownTotal, unknownTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _ = svc.Login(context.Background(), dto.LoginRequest{
			Email: "real-user@example.com", Password: "definitely-wrong-password", AppClientID: "admin-console-dev2",
		})
		knownTotal += time.Since(start)

		start = time.Now()
		_, _ = svc.Login(context.Background(), dto.LoginRequest{
			Email: "no-such-user@example.com", Password: "definitely-wrong-password", AppClientID: "admin-console-dev2",
		})
		unknownTotal += time.Since(start)
	}

	if !timingRatioWithinTolerance(unknownTotal, knownTotal) {
		t.Errorf("L1: unknown-email vs known-email+wrong-password timing not comparable "+
			"(unknown=%v, known=%v over %d iterations, ratio=%.2f) — "+
			"an unknown email must pay roughly the same bcrypt cost as a wrong password on a known email",
			unknownTotal, knownTotal, iterations, float64(unknownTotal)/float64(knownTotal))
	}
}

// TestAdminLogin_UnknownEmail_TimingParityWithWrongPassword mirrors the above
// for the admin-portal login path (identical not-found short-circuit existed
// in AdminLogin).
func TestAdminLogin_UnknownEmail_TimingParityWithWrongPassword(t *testing.T) {
	pw := "Str0ng!Passw0rd"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	admin := &model.User{
		ID: 2, Email: "admin@example.com", HashedPassword: hash,
		IsVerified: true, Role: model.UserRoleSuperadmin,
	}
	svc := newLoginSvc(t, admin)

	const iterations = 5
	var knownTotal, unknownTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _ = svc.AdminLogin(context.Background(), dto.AdminLoginRequest{
			Email: "admin@example.com", Password: "definitely-wrong-password",
		})
		knownTotal += time.Since(start)

		start = time.Now()
		_, _ = svc.AdminLogin(context.Background(), dto.AdminLoginRequest{
			Email: "no-such-admin@example.com", Password: "definitely-wrong-password",
		})
		unknownTotal += time.Since(start)
	}

	if !timingRatioWithinTolerance(unknownTotal, knownTotal) {
		t.Errorf("L1: AdminLogin unknown-email vs known-email+wrong-password timing not comparable "+
			"(unknown=%v, known=%v over %d iterations, ratio=%.2f)",
			unknownTotal, knownTotal, iterations, float64(unknownTotal)/float64(knownTotal))
	}
}

// TestLogin_UnknownEmail_CallsDummyBcryptCheck is a deterministic (non-timing)
// companion check: FindByEmail returning an error must still result in
// ErrInvalidCredentials (unchanged observable behaviour) — the L1 fix only
// changes internal timing, not the returned error.
func TestLogin_UnknownEmail_StillReturnsInvalidCredentials(t *testing.T) {
	user := &model.User{ID: 1, Email: "real-user@example.com", IsVerified: true}
	svc := newLoginSvc(t, user)

	_, err := svc.Login(context.Background(), dto.LoginRequest{
		Email: "no-such-user@example.com", Password: "whatever", AppClientID: "admin-console-dev2",
	})
	if err != ErrInvalidCredentials {
		t.Errorf("Login(unknown email) error = %v, want ErrInvalidCredentials", err)
	}
}
