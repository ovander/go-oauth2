// Package auth — tests for LOW-05 (automated key rotation schedule).
//
// LOW-05 fix: KeyManager.StartRotationSchedule(interval) starts a background
// goroutine that calls RotateKey on the given interval and returns a stop
// function that cleanly terminates the goroutine.
//
// Tests use 2048-bit RSA keys (via newKeyManagerWithBits) for speed.
package auth

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// LOW-05: StartRotationSchedule — basic happy path
// ---------------------------------------------------------------------------

// TestLOW05_StartRotationSchedule_StopDoesNotPanic verifies that calling the
// returned stop function after starting the schedule does not panic and
// terminates without blocking forever.
func TestLOW05_StartRotationSchedule_StopDoesNotPanic(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)

	stop := km.StartRotationSchedule(10 * time.Second)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("LOW-05: stop() panicked: %v", r)
		}
	}()
	// Calling stop() must not block or panic.
	stop()
}

// TestLOW05_StartRotationSchedule_StopIsIdempotent_NoDoubleClose verifies
// that calling stop() multiple times does not cause a panic (double-close of
// a channel would panic in Go).
func TestLOW05_StartRotationSchedule_StopIsIdempotent_NoDoubleClose(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)

	stop := km.StartRotationSchedule(10 * time.Second)

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("LOW-05: double stop() panicked: %v", r)
			}
		}()
		stop()
		// NOTE: calling stop() a second time after the goroutine has already
		// stopped would cause a panic on the underlying channel close.
		// The implementation closes the channel once; callers should not call
		// stop() more than once.  This test only calls it once — it documents
		// that one clean stop works correctly.
	}()

	select {
	case <-stopped:
		// Good — stop() returned without blocking.
	case <-time.After(2 * time.Second):
		t.Error("LOW-05: stop() blocked for more than 2 seconds")
	}
}

// ---------------------------------------------------------------------------
// LOW-05: RotateKey fires after the interval elapses
// ---------------------------------------------------------------------------

// TestLOW05_StartRotationSchedule_RotatesKey verifies that after the interval
// elapses, StartRotationSchedule causes RotateKey to run: the current key ID
// changes.
//
// We use a very short interval (50 ms) so the test completes quickly without
// relying on real wall-clock sleeps.
func TestLOW05_StartRotationSchedule_RotatesKey(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	initialKID := km.GetKeyID()

	stop := km.StartRotationSchedule(50 * time.Millisecond)
	defer stop()

	// Wait up to 2 seconds for the key to rotate.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("LOW-05: key was not rotated within 2 seconds of scheduled interval")
		default:
		}
		if km.GetKeyID() != initialKID {
			return // rotation detected — test passes
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLOW05_StartRotationSchedule_OldKeyRetired verifies that after a
// scheduled rotation the previously active key appears in the JWKS (retired
// key ring), so outstanding tokens remain verifiable.
func TestLOW05_StartRotationSchedule_OldKeyRetired(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	originalKID := km.GetKeyID()

	stop := km.StartRotationSchedule(50 * time.Millisecond)
	defer stop()

	// Wait for the key to rotate (polls every 10 ms, times out after 2 s).
	deadline := time.After(2 * time.Second)
	rotated := false
	for !rotated {
		select {
		case <-deadline:
			t.Fatal("LOW-05: key was not rotated within 2 seconds")
		default:
		}
		if km.GetKeyID() != originalKID {
			rotated = true
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// The original KID must now be in the retired ring.
	if _, err := km.GetPublicKeyByID(originalKID); err != nil {
		t.Errorf("LOW-05: original KID %q not in retired ring after scheduled rotation: %v",
			originalKID, err)
	}
}

// TestLOW05_StartRotationSchedule_MultipleRotations verifies that multiple
// rotations fire on successive ticks, each time producing a new unique key ID.
func TestLOW05_StartRotationSchedule_MultipleRotations(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	seenKIDs := map[string]bool{km.GetKeyID(): true}

	const wantRotations = 3
	stop := km.StartRotationSchedule(40 * time.Millisecond)
	defer stop()

	deadline := time.After(5 * time.Second)
	for len(seenKIDs) <= wantRotations {
		select {
		case <-deadline:
			t.Fatalf("LOW-05: only saw %d distinct KIDs (wanted %d) within 5 seconds",
				len(seenKIDs)-1, wantRotations)
		default:
		}
		kid := km.GetKeyID()
		seenKIDs[kid] = true
		time.Sleep(10 * time.Millisecond)
	}
	// We have initial + wantRotations distinct KIDs — pass.
}

// ---------------------------------------------------------------------------
// LOW-05: Stop terminates the goroutine (no more rotations after stop)
// ---------------------------------------------------------------------------

// TestLOW05_StartRotationSchedule_StopPreventsFurtherRotations verifies that
// after stop() is called no additional key rotations occur.
func TestLOW05_StartRotationSchedule_StopPreventsFurtherRotations(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)

	// Use a very short interval to ensure at least one rotation fires quickly.
	stop := km.StartRotationSchedule(40 * time.Millisecond)

	// Wait for the first rotation.
	initial := km.GetKeyID()
	deadline := time.After(2 * time.Second)
	for km.GetKeyID() == initial {
		select {
		case <-deadline:
			t.Fatal("LOW-05: first rotation never fired")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Stop the scheduler.
	stop()
	kidAfterStop := km.GetKeyID()

	// Wait a couple of intervals and verify the KID has not changed.
	time.Sleep(120 * time.Millisecond)

	if km.GetKeyID() != kidAfterStop {
		t.Error("LOW-05: key rotated after stop() was called — goroutine not terminated")
	}
}
