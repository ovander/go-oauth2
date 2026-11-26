package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// LOCKOUT_SOURCE_MODE (#403): failed sign-ins are counted per account and
// source, so a stranger hammering an account from one place locks only
// themselves out of it, not the owner.

type memSourceFailures struct {
	mu        sync.Mutex
	counts    map[string]int
	locks     map[string]time.Time
	lockErr   error
	recordErr error
}

func newMemSourceFailures() *memSourceFailures {
	return &memSourceFailures{counts: map[string]int{}, locks: map[string]time.Time{}}
}

func sourceKey(userID uint, source string) string { return fmt.Sprintf("%d|%s", userID, source) }

func (m *memSourceFailures) RecordFailure(_ context.Context, userID uint, source string, _ time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordErr != nil {
		return 0, m.recordErr
	}
	m.counts[sourceKey(userID, source)]++
	return m.counts[sourceKey(userID, source)], nil
}

func (m *memSourceFailures) Lock(_ context.Context, userID uint, source string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locks[sourceKey(userID, source)] = until
	m.counts[sourceKey(userID, source)] = 0
	return nil
}

func (m *memSourceFailures) LockedUntil(_ context.Context, userID uint, source string) (*time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockErr != nil {
		return nil, m.lockErr
	}
	if until, ok := m.locks[sourceKey(userID, source)]; ok && until.After(time.Now()) {
		return &until, nil
	}
	return nil, nil
}

func (m *memSourceFailures) Reset(_ context.Context, userID uint, source string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.counts, sourceKey(userID, source))
	return nil
}

func (m *memSourceFailures) DeleteStale(context.Context, time.Time) (int64, error) { return 0, nil }

// sourceAuditRepo keeps every audit event.
type sourceAuditRepo struct {
	repository.SecurityAuditLogRepository
	events []*model.SecurityAuditLog
}

func (c *sourceAuditRepo) Create(_ context.Context, log *model.SecurityAuditLog) error {
	c.events = append(c.events, log)
	return nil
}

func (c *sourceAuditRepo) lastOf(t model.SecurityEventType) *model.SecurityAuditLog {
	for i := len(c.events) - 1; i >= 0; i-- {
		if c.events[i].EventType == t {
			return c.events[i]
		}
	}
	return nil
}

func fromIP(ip string) context.Context {
	return context.WithValue(context.Background(), contextkeys.IPAddressKey, ip)
}

// sourceLockoutService is a service over one superadmin (re-authentication is
// the simplest password path) with a limit of 3 and the given mode.
func sourceLockoutService(t *testing.T, mode string) (*authService, *lockoutUserRepo, *memSourceFailures, *sourceAuditRepo) {
	t.Helper()
	repo := newLockoutUserRepo(lockoutTestUser(t, model.UserRoleSuperadmin))
	store := newMemSourceFailures()
	audit := &sourceAuditRepo{}
	s := &authService{userRepo: repo, maxFailedAttempts: 3, lockoutDuration: 15 * time.Minute, auditRepo: audit,
		tokenService: newTestTokenServiceForLockout(t)}
	s.SetLockoutSourcePolicy(mode, store)
	return s, repo, store, audit
}

func reauth(s *authService, ip, password string) error {
	_, err := s.ReAuthenticate(fromIP(ip), 5, password, "")
	return err
}

func TestSourceLockout_EnforceLocksOnlyTheSource(t *testing.T) {
	s, repo, _, audit := sourceLockoutService(t, lockoutSourceEnforce)
	const attacker, owner = "198.51.100.7", "203.0.113.20"

	for i := 1; i <= 2; i++ {
		if err := reauth(s, attacker, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password %d: %v", i, err)
		}
	}
	// The locking attempt is answered like any wrong password.
	if err := reauth(s, attacker, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("third wrong password: %v, want ErrInvalidCredentials", err)
	}
	ev := audit.lastOf(model.SecurityEventAccountLocked)
	if ev == nil || ev.Details["lock_scope"] != "source" || ev.Details["source"] != attacker {
		t.Fatalf("source lock not audited: %+v", ev)
	}
	if repo.users[5].IsLocked() || repo.users[5].FailedLoginAttempts != 0 {
		t.Fatalf("the account itself was locked or counted: locked=%v count=%d",
			repo.users[5].IsLocked(), repo.users[5].FailedLoginAttempts)
	}
	// The owner, elsewhere, signs in.
	if err := reauth(s, owner, lockoutTestPassword); err != nil {
		t.Fatalf("owner from another source: %v", err)
	}
	// The locked source: a wrong password learns nothing, the right one is
	// told about the lock.
	if err := reauth(s, attacker, "wrong"); !errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrAccountLocked) {
		t.Fatalf("wrong password from the locked source: %v, want ErrInvalidCredentials", err)
	}
	if ev := audit.lastOf(model.SecurityEventLoginFailed); ev == nil || ev.Details["lock_scope"] != "source" ||
		ev.Details["source"] != attacker || ev.Details["password_verified"] != false {
		t.Fatalf("attempt from the locked source not audited: %+v", ev)
	}
	if err := reauth(s, attacker, lockoutTestPassword); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("right password from the locked source: %v, want ErrAccountLocked", err)
	}
	if ev := audit.lastOf(model.SecurityEventLoginFailed); ev == nil || ev.Details["lock_scope"] != "source" ||
		ev.Details["source"] != attacker || ev.Details["password_verified"] != true {
		t.Fatalf("right password from the locked source not audited with its source: %+v", ev)
	}
}

func TestSourceLockout_EnforceIPv6CountsThe64(t *testing.T) {
	s, _, _, audit := sourceLockoutService(t, lockoutSourceEnforce)
	for i, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::3"} {
		// The locking attempt too is answered like any wrong password.
		if err := reauth(s, ip, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d from %s: %v, want ErrInvalidCredentials", i+1, ip, err)
		}
		if locked := audit.lastOf(model.SecurityEventAccountLocked) != nil; locked != (i == 2) {
			t.Fatalf("attempt %d from %s: locked %v, want %v", i+1, ip, locked, i == 2)
		}
	}
	// An attempt from another address in the locked /64 is audited with the
	// /64 it was refused for.
	if err := reauth(s, "2001:db8:1:2::9", lockoutTestPassword); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("right password from the locked /64: %v, want ErrAccountLocked", err)
	}
	// password_verified is only on the refused attempt's row: the counted
	// failures before it carry the same source.
	if ev := audit.lastOf(model.SecurityEventLoginFailed); ev == nil || ev.Details["source"] != "2001:db8:1:2::/64" ||
		ev.Details["lock_scope"] != "source" || ev.Details["password_verified"] != true {
		t.Fatalf("locked /64 not audited: %+v", ev)
	}
	if err := reauth(s, "2001:db8:1:3::1", lockoutTestPassword); err != nil {
		t.Fatalf("another /64: %v", err)
	}
}

func TestSourceLockout_SuccessResetsTheSource(t *testing.T) {
	s, _, _, _ := sourceLockoutService(t, lockoutSourceEnforce)
	const ip = "198.51.100.7"
	for round := 0; round < 2; round++ {
		for i := 0; i < 2; i++ {
			if err := reauth(s, ip, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("round %d wrong %d: %v", round, i, err)
			}
		}
		if err := reauth(s, ip, lockoutTestPassword); err != nil {
			t.Fatalf("round %d success: %v (the count was not reset)", round, err)
		}
	}
}

// An admin block (an account-wide lock) still applies under enforce.
func TestSourceLockout_EnforceKeepsAccountLocks(t *testing.T) {
	s, repo, _, _ := sourceLockoutService(t, lockoutSourceEnforce)
	until := time.Now().Add(time.Hour)
	repo.users[5].LockedUntil = &until
	if err := reauth(s, "203.0.113.20", lockoutTestPassword); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("blocked account: %v, want ErrAccountLocked", err)
	}
}

// A store that cannot say whether the source is locked refuses (fail closed).
func TestSourceLockout_EnforceStoreErrorRefuses(t *testing.T) {
	s, _, store, _ := sourceLockoutService(t, lockoutSourceEnforce)
	store.lockErr = errors.New("database unavailable")
	if err := reauth(s, "203.0.113.20", lockoutTestPassword); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("store error: %v, want a refusal", err)
	}
}

func TestSourceLockout_ObserveKeepsTheAccountLockAndAudits(t *testing.T) {
	s, repo, _, audit := sourceLockoutService(t, lockoutSourceObserve)
	const ip = "198.51.100.7"
	for i := 0; i < 2; i++ {
		_ = reauth(s, ip, "wrong")
	}
	if ev := audit.lastOf(model.SecurityEventLoginFailed); ev == nil || ev.Details["source_failed_attempts"] != 2 || ev.Details["failed_attempts"] != 2 {
		t.Fatalf("observe details: %+v", ev)
	}
	if err := reauth(s, ip, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("observe, the locking attempt: %v, want ErrInvalidCredentials", err)
	}
	if !repo.users[5].IsLocked() {
		t.Fatal("observe must lock the account as before")
	}
	if ev := audit.lastOf(model.SecurityEventAccountLocked); ev == nil || ev.Details["source_would_lock"] != true || ev.Details["lock_scope"] != nil {
		t.Fatalf("observe lock details: %+v", ev)
	}
}

func TestSourceLockout_OffLeavesTheStoreAlone(t *testing.T) {
	s, repo, store, _ := sourceLockoutService(t, lockoutSourceOff)
	for i := 0; i < 3; i++ {
		_ = reauth(s, "198.51.100.7", "wrong")
	}
	if !repo.users[5].IsLocked() || len(store.counts) != 0 {
		t.Fatalf("off: locked=%v, store counts %v", repo.users[5].IsLocked(), store.counts)
	}
}

func TestLoginSource(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":           "203.0.113.9",
		"::ffff:203.0.113.9":    "203.0.113.9",
		"2001:db8:1:2:3:4:5:6":  "2001:db8:1:2::/64",
		"fe80::1%eth0":          "fe80::/64",
		"":                      loginSourceUnknown,
		"not-an-address":        loginSourceUnknown,
		"203.0.113.9:443":       loginSourceUnknown,
		"2001:db8:1:2::/64":     loginSourceUnknown,
		"2001:0db8:0001:0002::": "2001:db8:1:2::/64",
	} {
		if got := loginSource(fromIP(in)); got != want {
			t.Errorf("loginSource(%q) = %q, want %q", in, got, want)
		}
	}
}

// A failure that cannot be counted per source is counted on the account, as
// in off: a broken store must not make guessing unlimited.
func TestSourceLockout_EnforceStoreWriteErrorCountsOnTheAccount(t *testing.T) {
	s, repo, store, audit := sourceLockoutService(t, lockoutSourceEnforce)
	store.recordErr = errors.New("database unavailable")
	for i := 0; i < 2; i++ {
		if err := reauth(s, "198.51.100.7", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password %d: %v", i+1, err)
		}
	}
	if err := reauth(s, "198.51.100.7", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("third wrong password with the store down: %v, want ErrInvalidCredentials", err)
	}
	if !repo.users[5].IsLocked() {
		t.Fatal("the account was not locked while the source store failed")
	}
	if ev := audit.lastOf(model.SecurityEventAccountLocked); ev == nil || ev.Details["source_store_error"] != true {
		t.Fatalf("lock details: %+v", ev)
	}
}
