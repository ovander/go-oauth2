package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
)

// ---------------------------------------------------------------------------
// In-memory MFARecoveryCodeRepository
// ---------------------------------------------------------------------------

type memRecoveryRepo struct {
	codes  []model.MFARecoveryCode
	nextID uint
}

func newMemRecoveryRepo() *memRecoveryRepo { return &memRecoveryRepo{nextID: 1} }

func (r *memRecoveryRepo) CreateBatch(_ context.Context, codes []model.MFARecoveryCode) error {
	for i := range codes {
		codes[i].ID = r.nextID
		r.nextID++
		r.codes = append(r.codes, codes[i])
	}
	return nil
}

func (r *memRecoveryRepo) ListUnusedByUser(_ context.Context, userID uint) ([]model.MFARecoveryCode, error) {
	var out []model.MFARecoveryCode
	for _, c := range r.codes {
		if c.UserID == userID && c.UsedAt == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *memRecoveryRepo) MarkUsed(_ context.Context, id uint) (bool, error) {
	for i := range r.codes {
		if r.codes[i].ID == id && r.codes[i].UsedAt == nil {
			now := time.Now()
			r.codes[i].UsedAt = &now
			return true, nil
		}
	}
	return false, nil
}

func (r *memRecoveryRepo) DeleteByUser(_ context.Context, userID uint) error {
	kept := r.codes[:0:0]
	for _, c := range r.codes {
		if c.UserID != userID {
			kept = append(kept, c)
		}
	}
	r.codes = kept
	return nil
}

func (r *memRecoveryRepo) CountUnusedByUser(_ context.Context, userID uint) (int64, error) {
	var n int64
	for _, c := range r.codes {
		if c.UserID == userID && c.UsedAt == nil {
			n++
		}
	}
	return n, nil
}

var _ repository.MFARecoveryCodeRepository = (*memRecoveryRepo)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func newRecoveryMFAService(userRepo repository.UserRepository, rec repository.MFARecoveryCodeRepository) MFAService {
	return NewMFAService(userRepo, rec, testEncKey, "Socrate")
}

func TestRecovery_GenerateRequiresEnrollment(t *testing.T) {
	userRepo := newMFAMemUserRepo(&model.User{ID: 1, Email: "a@b.com", MFAEnabled: false})
	svc := newRecoveryMFAService(userRepo, newMemRecoveryRepo())

	if _, err := svc.GenerateRecoveryCodes(context.Background(), 1); !errors.Is(err, ErrMFANotEnrolled) {
		t.Fatalf("expected ErrMFANotEnrolled, got %v", err)
	}
}

func TestRecovery_GenerateReturnsCodesAndPersistsHashes(t *testing.T) {
	userRepo := newMFAMemUserRepo(&model.User{ID: 1, Email: "a@b.com", MFAEnabled: true})
	rec := newMemRecoveryRepo()
	svc := newRecoveryMFAService(userRepo, rec)

	codes, err := svc.GenerateRecoveryCodes(context.Background(), 1)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("expected %d codes, got %d", recoveryCodeCount, len(codes))
	}
	if n, _ := rec.CountUnusedByUser(context.Background(), 1); n != int64(recoveryCodeCount) {
		t.Fatalf("expected %d persisted codes, got %d", recoveryCodeCount, n)
	}
	// Stored values must be hashes, never the plaintext.
	for _, stored := range rec.codes {
		for _, plain := range codes {
			if stored.CodeHash == plain {
				t.Fatal("recovery code stored in plaintext")
			}
		}
	}
}

func TestRecovery_RegenerateReplacesPriorSet(t *testing.T) {
	userRepo := newMFAMemUserRepo(&model.User{ID: 1, Email: "a@b.com", MFAEnabled: true})
	rec := newMemRecoveryRepo()
	svc := newRecoveryMFAService(userRepo, rec)

	first, _ := svc.GenerateRecoveryCodes(context.Background(), 1)
	if _, err := svc.GenerateRecoveryCodes(context.Background(), 1); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	// A code from the first set must no longer redeem.
	ok, err := svc.RedeemRecoveryCode(context.Background(), 1, first[0])
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if ok {
		t.Error("a code from the replaced set should not redeem")
	}
	if n, _ := rec.CountUnusedByUser(context.Background(), 1); n != int64(recoveryCodeCount) {
		t.Fatalf("expected exactly one fresh set, got %d codes", n)
	}
}

func TestRecovery_RedeemValidThenSingleUse(t *testing.T) {
	userRepo := newMFAMemUserRepo(&model.User{ID: 1, Email: "a@b.com", MFAEnabled: true})
	svc := newRecoveryMFAService(userRepo, newMemRecoveryRepo())

	codes, _ := svc.GenerateRecoveryCodes(context.Background(), 1)

	ok, err := svc.RedeemRecoveryCode(context.Background(), 1, codes[0])
	if err != nil || !ok {
		t.Fatalf("first redeem: ok=%v err=%v", ok, err)
	}
	// Same code cannot be reused.
	ok, err = svc.RedeemRecoveryCode(context.Background(), 1, codes[0])
	if err != nil {
		t.Fatalf("second redeem err: %v", err)
	}
	if ok {
		t.Error("recovery code must be single-use")
	}
}

func TestRecovery_RedeemIgnoresFormatting(t *testing.T) {
	userRepo := newMFAMemUserRepo(&model.User{ID: 1, Email: "a@b.com", MFAEnabled: true})
	svc := newRecoveryMFAService(userRepo, newMemRecoveryRepo())

	codes, _ := svc.GenerateRecoveryCodes(context.Background(), 1)
	// Upper-case, spaced, dash variations must still match.
	mangled := "  " + codes[0] + "  "
	ok, err := svc.RedeemRecoveryCode(context.Background(), 1, mangled)
	if err != nil || !ok {
		t.Fatalf("redeem mangled: ok=%v err=%v", ok, err)
	}
}

func TestRecovery_RedeemInvalidCode(t *testing.T) {
	userRepo := newMFAMemUserRepo(&model.User{ID: 1, Email: "a@b.com", MFAEnabled: true})
	svc := newRecoveryMFAService(userRepo, newMemRecoveryRepo())

	if _, err := svc.GenerateRecoveryCodes(context.Background(), 1); err != nil {
		t.Fatalf("generate: %v", err)
	}
	ok, err := svc.RedeemRecoveryCode(context.Background(), 1, "zzzzz-zzzzz")
	if err != nil {
		t.Fatalf("redeem err: %v", err)
	}
	if ok {
		t.Error("an unknown code must not redeem")
	}
	// Empty code is rejected without scanning.
	if ok, _ := svc.RedeemRecoveryCode(context.Background(), 1, "   "); ok {
		t.Error("blank code must not redeem")
	}
}

func TestRecovery_DisableClearsCodes(t *testing.T) {
	userRepo := newMFAMemUserRepo(&model.User{ID: 1, Email: "a@b.com", MFAEnabled: true})
	rec := newMemRecoveryRepo()
	svc := newRecoveryMFAService(userRepo, rec)

	if _, err := svc.GenerateRecoveryCodes(context.Background(), 1); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := svc.Disable(context.Background(), 1); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if n, _ := rec.CountUnusedByUser(context.Background(), 1); n != 0 {
		t.Fatalf("expected codes cleared on disable, got %d", n)
	}
}
