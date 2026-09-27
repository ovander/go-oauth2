package policy

import (
	"context"
	"errors"
	"testing"
	"time"
)

var allowAll = []Rule{{ID: "all", Effect: EffectAllow, Actions: []string{"*"}}}
var denyAll = []Rule{{ID: "none", Effect: EffectDeny, Actions: []string{"*"}}}

func TestService_EnsureBaseline_Idempotent(t *testing.T) {
	store := NewMemoryStore()
	s := NewService(store, ModeShadow, time.Minute)
	ctx := context.Background()

	seeded, err := s.EnsureBaseline(ctx)
	if err != nil || !seeded {
		t.Fatalf("first EnsureBaseline: seeded=%v err=%v", seeded, err)
	}
	seeded, err = s.EnsureBaseline(ctx)
	if err != nil || seeded {
		t.Fatalf("second EnsureBaseline: seeded=%v err=%v, want a no-op", seeded, err)
	}
	v, err := s.Current(ctx)
	if err != nil || v.Version != 1 || len(v.Rules) != len(Baseline()) {
		t.Fatalf("current = %+v, %v; want the baseline as version 1", v, err)
	}
}

func TestService_Save_OptimisticConcurrency(t *testing.T) {
	store := NewMemoryStore()
	s := NewService(store, ModeShadow, time.Minute)
	ctx := context.Background()
	if _, err := s.EnsureBaseline(ctx); err != nil {
		t.Fatal(err)
	}

	// Two editors both loaded version 1.
	v2, err := s.Save(ctx, 1, allowAll, "first editor", 10)
	if err != nil || v2.Version != 2 {
		t.Fatalf("first save: %+v, %v", v2, err)
	}
	if _, err := s.Save(ctx, 1, denyAll, "second editor", 11); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("second save from a stale base: err = %v, want ErrVersionConflict", err)
	}
	// A base from the future is a conflict too, not a gap in the history.
	if _, err := s.Save(ctx, 9, denyAll, "", 11); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("save from a future base: err = %v, want ErrVersionConflict", err)
	}
}

func TestService_Save_RejectsInvalidRules(t *testing.T) {
	s := NewService(NewMemoryStore(), ModeShadow, time.Minute)
	_, err := s.Save(context.Background(), 0, []Rule{{ID: "x", Effect: "maybe", Actions: []string{"*"}}}, "", 1)
	var vf *ValidationFailed
	if !errors.As(err, &vf) || len(vf.Errors) == 0 {
		t.Fatalf("err = %v, want *ValidationFailed", err)
	}
}

func TestService_SeesItsOwnSaveImmediately_AndOthersAfterRefresh(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	s := NewService(store, ModeEnforce, 10*time.Second)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := s.EnsureBaseline(ctx); err != nil {
		t.Fatal(err)
	}

	in := adminInput("admin", "GET /anything")
	if d, _ := s.Decide(ctx, in); d.Allow {
		t.Fatalf("baseline should not cover %q: %+v", in.Action, d)
	}

	// Local save: visible on the very next decision.
	if _, err := s.Save(ctx, 1, allowAll, "", 1); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.Decide(ctx, in); !d.Allow || d.Version != 2 {
		t.Fatalf("after local save: %+v, want allow at v2", d)
	}

	// Another instance saves version 3 directly in the store.
	_ = store.Insert(ctx, &Version{Version: 3, Rules: denyAll})
	if d, _ := s.Decide(ctx, in); d.Version != 2 {
		t.Fatalf("within the refresh interval: v%d, want still v2", d.Version)
	}
	now = now.Add(11 * time.Second)
	if d, _ := s.Decide(ctx, in); d.Allow || d.Version != 3 {
		t.Fatalf("after the refresh interval: %+v, want deny at v3", d)
	}
}

func TestService_StoreOutage_KeepsServingLoadedVersion(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	s := NewService(store, ModeEnforce, 10*time.Second)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := s.Save(ctx, 0, allowAll, "", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Engine(ctx); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	store.failRead = true
	store.mu.Unlock()
	now = now.Add(time.Minute)

	d, err := s.Decide(ctx, adminInput("admin", "x"))
	if err != nil || !d.Allow {
		t.Fatalf("during outage: %+v, %v; want the loaded version to keep deciding", d, err)
	}
	// And it backs off rather than hitting the failing store on every call.
	store.mu.Lock()
	before := store.reads
	store.mu.Unlock()
	for i := 0; i < 5; i++ {
		_, _ = s.Decide(ctx, adminInput("admin", "x"))
	}
	store.mu.Lock()
	after := store.reads
	store.mu.Unlock()
	if after != before {
		t.Fatalf("store read %d more times during the back-off interval, want 0", after-before)
	}
}

func TestService_NothingLoaded_IsAnError(t *testing.T) {
	s := NewService(NewMemoryStore(), ModeEnforce, time.Minute)
	d, err := s.Decide(context.Background(), adminInput("admin", "x"))
	if !errors.Is(err, ErrNoPolicy) || d.Allow || d.Reason != ReasonPolicyUnloaded {
		t.Fatalf("got %+v, %v; want a deny with ErrNoPolicy", d, err)
	}
}

func TestService_Restore_IsAForwardWrite(t *testing.T) {
	store := NewMemoryStore()
	s := NewService(store, ModeShadow, time.Minute)
	ctx := context.Background()
	_, _ = s.EnsureBaseline(ctx)
	_, _ = s.Save(ctx, 1, allowAll, "", 1)

	v, err := s.Restore(ctx, 1, 2, 5)
	if err != nil || v.Version != 3 || len(v.Rules) != len(Baseline()) {
		t.Fatalf("restore: %+v, %v; want version 3 holding version 1's rules", v, err)
	}
	if _, err := s.Get(ctx, 2); err != nil {
		t.Fatalf("version 2 must still exist after a restore: %v", err)
	}
}

func TestService_SimulateDraft_DoesNotTouchTheStore(t *testing.T) {
	store := NewMemoryStore()
	s := NewService(store, ModeShadow, time.Minute)
	d, trace, err := s.Simulate(context.Background(), adminInput("admin", "x"), denyAll)
	if err != nil || d.Allow || len(trace) != 1 {
		t.Fatalf("simulate draft: %+v %+v %v", d, trace, err)
	}
	if n, _ := store.LatestVersion(context.Background()); n != 0 {
		t.Fatalf("simulating a draft stored version %d", n)
	}
}
