package repository_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/repository"
)

// ---------------------------------------------------------------------------
// ErrTokenAlreadyUsed sentinel
// ---------------------------------------------------------------------------

func TestErrTokenAlreadyUsed_IsDefined(t *testing.T) {
	if repository.ErrTokenAlreadyUsed == nil {
		t.Fatal("repository.ErrTokenAlreadyUsed must not be nil")
	}
}

func TestErrTokenAlreadyUsed_Message(t *testing.T) {
	const want = "token has already been used"
	if got := repository.ErrTokenAlreadyUsed.Error(); got != want {
		t.Errorf("ErrTokenAlreadyUsed.Error() = %q, want %q", got, want)
	}
}

func TestErrTokenAlreadyUsed_IsDistinctFromOtherErrors(t *testing.T) {
	unrelated := errors.New("some other error")
	if errors.Is(unrelated, repository.ErrTokenAlreadyUsed) {
		t.Error("an unrelated error should not match ErrTokenAlreadyUsed via errors.Is")
	}
}

func TestErrTokenAlreadyUsed_WrappedErrorIsDetectable(t *testing.T) {
	// Callers that wrap the sentinel (e.g. fmt.Errorf("…: %w", ErrTokenAlreadyUsed))
	// must still be detectable by errors.Is.
	wrapped := errors.Join(errors.New("outer context"), repository.ErrTokenAlreadyUsed)
	if !errors.Is(wrapped, repository.ErrTokenAlreadyUsed) {
		t.Error("errors.Is must detect ErrTokenAlreadyUsed when it is wrapped")
	}
}

// ---------------------------------------------------------------------------
// In-memory mock that simulates atomic single-use enforcement
// ---------------------------------------------------------------------------

// inMemoryUsedTokenRepository is an in-memory implementation of
// UsedTokenRepository that enforces single-use semantics through a mutex +
// map — equivalent in behaviour (if not in implementation) to the production
// INSERT … ON CONFLICT DO NOTHING approach.
type inMemoryUsedTokenRepository struct {
	mu   sync.Mutex
	used map[string]bool
}

func newInMemoryUsedTokenRepository() *inMemoryUsedTokenRepository {
	return &inMemoryUsedTokenRepository{used: make(map[string]bool)}
}

func (r *inMemoryUsedTokenRepository) MarkAsUsed(
	_ context.Context,
	tokenJTI, _ string,
	_ uint,
	_ time.Time,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used[tokenJTI] {
		return repository.ErrTokenAlreadyUsed
	}
	r.used[tokenJTI] = true
	return nil
}

func (r *inMemoryUsedTokenRepository) IsUsed(_ context.Context, tokenJTI string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.used[tokenJTI], nil
}

func (r *inMemoryUsedTokenRepository) DeleteExpired(_ context.Context) (int64, error) {
	return 0, nil
}

// Compile-time interface check.
var _ repository.UsedTokenRepository = (*inMemoryUsedTokenRepository)(nil)

// ---------------------------------------------------------------------------
// Behaviour tests against the in-memory mock
// ---------------------------------------------------------------------------

func TestInMemoryUsedTokenRepository_FirstCall_Succeeds(t *testing.T) {
	repo := newInMemoryUsedTokenRepository()
	err := repo.MarkAsUsed(context.Background(), "jti-1", "email_verification", 42, time.Now().Add(time.Hour))
	if err != nil {
		t.Errorf("first MarkAsUsed call returned %v, want nil", err)
	}
}

func TestInMemoryUsedTokenRepository_SecondCall_ErrTokenAlreadyUsed(t *testing.T) {
	// The second call with the same JTI must be rejected with ErrTokenAlreadyUsed.
	repo := newInMemoryUsedTokenRepository()
	jti := "jti-duplicate"
	_ = repo.MarkAsUsed(context.Background(), jti, "password_reset", 7, time.Now().Add(time.Hour))

	err := repo.MarkAsUsed(context.Background(), jti, "password_reset", 7, time.Now().Add(time.Hour))
	if !errors.Is(err, repository.ErrTokenAlreadyUsed) {
		t.Errorf("second MarkAsUsed call returned %v, want %v", err, repository.ErrTokenAlreadyUsed)
	}
}

func TestInMemoryUsedTokenRepository_DifferentJTIs_IndependentlyTracked(t *testing.T) {
	// Different JTIs are independent; using one must not block the other.
	repo := newInMemoryUsedTokenRepository()
	_ = repo.MarkAsUsed(context.Background(), "jti-a", "email_verification", 1, time.Now().Add(time.Hour))

	err := repo.MarkAsUsed(context.Background(), "jti-b", "email_verification", 2, time.Now().Add(time.Hour))
	if err != nil {
		t.Errorf("MarkAsUsed for different JTI returned %v, want nil", err)
	}
}

func TestInMemoryUsedTokenRepository_IsUsed_ReflectsState(t *testing.T) {
	repo := newInMemoryUsedTokenRepository()
	jti := "jti-check"

	used, _ := repo.IsUsed(context.Background(), jti)
	if used {
		t.Error("IsUsed returned true before token was marked used")
	}

	_ = repo.MarkAsUsed(context.Background(), jti, "email_verification", 3, time.Now().Add(time.Hour))

	used, _ = repo.IsUsed(context.Background(), jti)
	if !used {
		t.Error("IsUsed returned false after token was marked used")
	}
}

func TestInMemoryUsedTokenRepository_ConcurrentCalls_AtMostOneWins(t *testing.T) {
	// N goroutines racing on the same JTI: exactly one must succeed; the rest
	// must receive ErrTokenAlreadyUsed.  This validates the atomicity contract.
	const goroutines = 20
	repo := newInMemoryUsedTokenRepository()
	jti := "jti-concurrent"

	type result struct{ err error }
	results := make(chan result, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	// Use a gate to maximise concurrency between goroutines.
	gate := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-gate // wait for the gun
			results <- result{err: repo.MarkAsUsed(
				context.Background(), jti, "email_verification", 1, time.Now().Add(time.Hour),
			)}
		}()
	}

	close(gate) // fire
	wg.Wait()
	close(results)

	successes := 0
	for r := range results {
		if r.err == nil {
			successes++
		} else if !errors.Is(r.err, repository.ErrTokenAlreadyUsed) {
			t.Errorf("unexpected error: %v", r.err)
		}
	}

	if successes != 1 {
		t.Errorf("expected exactly 1 success across %d concurrent calls, got %d", goroutines, successes)
	}
}
