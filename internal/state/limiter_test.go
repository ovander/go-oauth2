package state

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore is an in-memory RateLimitStore for exercising the adapter's
// decisions without a database.
type fakeStore struct {
	mu     sync.Mutex
	counts map[string]int
	err    error
}

func newFakeStore() *fakeStore { return &fakeStore{counts: map[string]int{}} }

func (f *fakeStore) Incr(_ context.Context, key string, window time.Duration) (int, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, time.Time{}, f.err
	}
	f.counts[key]++
	return f.counts[key], windowStart(time.Now(), window).Add(window), nil
}

func (f *fakeStore) Peek(_ context.Context, key string, window time.Duration) (int, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, time.Time{}, f.err
	}
	return f.counts[key], windowStart(time.Now(), window).Add(window), nil
}

func (f *fakeStore) Sweep(context.Context) (int64, error) { return 0, f.err }

func (f *fakeStore) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func TestStoreLimiter_AllowsUpToTheLimit(t *testing.T) {
	l := NewStoreLimiter(newFakeStore(), "login", 3, time.Minute)

	for i := 1; i <= 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d was denied; the limit is 3", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("the 4th request was allowed past a limit of 3")
	}
	// A different key has its own budget.
	if !l.Allow("5.6.7.8") {
		t.Fatal("a different key was denied; budgets must be per key")
	}
}

// The namespace is what keeps the login, signup and token limiters apart even
// though they share one table.
func TestStoreLimiter_NamespacesAreIndependent(t *testing.T) {
	store := newFakeStore()
	login := NewStoreLimiter(store, "login", 1, time.Minute)
	signup := NewStoreLimiter(store, "signup", 1, time.Minute)

	if !login.Allow("ip") {
		t.Fatal("first login request denied")
	}
	if !signup.Allow("ip") {
		t.Fatal("the signup limiter shares a budget with login")
	}
	if login.Allow("ip") {
		t.Fatal("the second login request should be denied")
	}
}

func TestStoreLimiter_RemainingAndReset(t *testing.T) {
	l := NewStoreLimiter(newFakeStore(), "login", 3, time.Minute)

	if got := l.RemainingRequests("ip"); got != 3 {
		t.Errorf("remaining before any request = %d, want 3", got)
	}
	l.Allow("ip")
	if got := l.RemainingRequests("ip"); got != 2 {
		t.Errorf("remaining after one request = %d, want 2", got)
	}
	// Never negative, even once over the limit.
	for i := 0; i < 5; i++ {
		l.Allow("ip")
	}
	if got := l.RemainingRequests("ip"); got != 0 {
		t.Errorf("remaining when over the limit = %d, want 0", got)
	}

	reset := l.ResetTime("ip")
	if !reset.After(time.Now()) {
		t.Errorf("reset time %v is not in the future", reset)
	}
	if d := time.Until(reset); d > time.Minute {
		t.Errorf("reset is %v away, longer than the window", d)
	}
}

// The rate limiter fails OPEN: the endpoints it protects need the same database,
// so a store outage means there is nothing left to brute-force, and denying
// would turn a database blip into a self-inflicted outage.
func TestStoreLimiter_FailsOpenOnStoreError(t *testing.T) {
	store := newFakeStore()
	l := NewStoreLimiter(store, "login", 1, time.Minute)

	if !l.Allow("ip") {
		t.Fatal("first request denied")
	}
	if l.Allow("ip") {
		t.Fatal("second request should be denied while the store works")
	}

	store.fail(errors.New("connection refused"))
	if !l.Allow("ip") {
		t.Fatal("the limiter failed closed on a store error; it must fail open")
	}
	// The headers stay sane rather than reporting nonsense.
	if got := l.RemainingRequests("ip"); got != 1 {
		t.Errorf("remaining during an outage = %d, want the full limit", got)
	}
	if !l.ResetTime("ip").After(time.Now()) {
		t.Error("reset time during an outage is not in the future")
	}
}

func TestStoreLimiter_LimitAndStop(t *testing.T) {
	l := NewStoreLimiter(newFakeStore(), "login", 7, time.Minute)
	if l.Limit() != 7 {
		t.Errorf("Limit() = %d, want 7", l.Limit())
	}
	l.Stop() // must not panic
}

// Concurrent callers must not lose counts — the store is the serialization
// point, and the adapter adds no racy state of its own.
func TestStoreLimiter_ConcurrentAllow(t *testing.T) {
	store := newFakeStore()
	l := NewStoreLimiter(store, "login", 50, time.Minute)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("ip") {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed != 50 {
		t.Errorf("%d of 100 concurrent requests allowed, want exactly 50", allowed)
	}
}

func TestNormalizeBackend(t *testing.T) {
	for in, want := range map[string]string{
		"postgres":   BackendPostgres,
		"POSTGRES":   BackendPostgres,
		" postgres ": BackendPostgres,
		"memory":     BackendMemory,
		"":           BackendMemory,
		// A typo must fall back to memory rather than silently changing where
		// security state lives.
		"postgress": BackendMemory,
		"redis":     BackendMemory,
	} {
		if got := NormalizeBackend(in); got != want {
			t.Errorf("NormalizeBackend(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every instance must compute the same window boundary without coordinating,
// which is why truncation is on the absolute clock.
func TestWindowStart_IsStableAcrossCallers(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 34, 56, 789, time.UTC)
	if got := windowStart(now, time.Minute); !got.Equal(time.Date(2026, 9, 4, 12, 34, 0, 0, time.UTC)) {
		t.Errorf("minute window start = %v", got)
	}
	if got := windowStart(now, time.Hour); !got.Equal(time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("hour window start = %v", got)
	}
	// A zero window must not divide by zero.
	if got := windowStart(now, 0); got.IsZero() {
		t.Error("a zero window produced a zero start")
	}
	// Two callers a few milliseconds apart agree.
	a := windowStart(now, time.Minute)
	b := windowStart(now.Add(3*time.Millisecond), time.Minute)
	if !a.Equal(b) {
		t.Errorf("window start is not stable: %v vs %v", a, b)
	}
}

func TestKey(t *testing.T) {
	if got := Key("login", "1.2.3.4"); got != "login:1.2.3.4" {
		t.Errorf("Key() = %q", got)
	}
	if !strings.HasPrefix(Key("token", "x"), "token:") {
		t.Error("Key lost its namespace")
	}
}
