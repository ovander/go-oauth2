// Package contextkeys — tests for M-07: typed context keys must not collide
// with raw strings that happen to have the same text value.
//
// M-07 fix: auth.go and oauth_handler.go previously looked up context values
// with raw string literals like `r.Context().Value("jwt_claims")`.  The typed
// contextKey type ensures that only code that imports this package — and uses
// the exported constants — can retrieve these values, preventing accidental
// cross-package interference.
package contextkeys

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// Typed key isolation: same text, different type → different slot
// ---------------------------------------------------------------------------

func TestTypedKey_DoesNotCollideWithRawString(t *testing.T) {
	t.Parallel()
	// Store a value under the typed JWTClaimsKey.
	ctx := context.WithValue(context.Background(), JWTClaimsKey, "the-claims")

	// Attempting to retrieve it with the equivalent raw string must return nil.
	got := ctx.Value("jwt_claims")
	if got != nil {
		t.Errorf("raw string %q retrieved a value stored under the typed key — collision detected", "jwt_claims")
	}
}

func TestTypedKey_RetrievedWithTypedKey(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), JWTClaimsKey, "my-claims-value")

	got, ok := ctx.Value(JWTClaimsKey).(string)
	if !ok || got != "my-claims-value" {
		t.Errorf("JWTClaimsKey lookup = (%q, %v), want (%q, true)", got, ok, "my-claims-value")
	}
}

func TestTypedKey_UserIDKey_NoCollision(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), UserIDKey, uint(99))

	// Raw string must not retrieve it.
	if ctx.Value("user_id") != nil {
		t.Error("raw string 'user_id' must not retrieve value stored under UserIDKey")
	}
	// Typed key must retrieve it.
	id, ok := ctx.Value(UserIDKey).(uint)
	if !ok || id != 99 {
		t.Errorf("UserIDKey lookup = (%d, %v), want (99, true)", id, ok)
	}
}

func TestTypedKey_UserRoleKey_NoCollision(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), UserRoleKey, "admin")

	if ctx.Value("user_role") != nil {
		t.Error("raw string 'user_role' must not retrieve value stored under UserRoleKey")
	}
	role, ok := ctx.Value(UserRoleKey).(string)
	if !ok || role != "admin" {
		t.Errorf("UserRoleKey lookup = (%q, %v), want (admin, true)", role, ok)
	}
}

func TestTypedKey_DifferentTypedKeys_DoNotInterfere(t *testing.T) {
	t.Parallel()
	// Even though the string representations differ, verify orthogonality
	// when multiple keys are stored in the same context.
	ctx := context.Background()
	ctx = context.WithValue(ctx, JWTClaimsKey, "claims-value")
	ctx = context.WithValue(ctx, UserIDKey, uint(7))
	ctx = context.WithValue(ctx, UserRoleKey, "editor")
	ctx = context.WithValue(ctx, AppIDKey, uint(42))

	if v, ok := ctx.Value(JWTClaimsKey).(string); !ok || v != "claims-value" {
		t.Errorf("JWTClaimsKey = (%q, %v), want (claims-value, true)", v, ok)
	}
	if v, ok := ctx.Value(UserIDKey).(uint); !ok || v != 7 {
		t.Errorf("UserIDKey = (%d, %v), want (7, true)", v, ok)
	}
	if v, ok := ctx.Value(UserRoleKey).(string); !ok || v != "editor" {
		t.Errorf("UserRoleKey = (%q, %v), want (editor, true)", v, ok)
	}
	if v, ok := ctx.Value(AppIDKey).(uint); !ok || v != 42 {
		t.Errorf("AppIDKey = (%d, %v), want (42, true)", v, ok)
	}
}

// ---------------------------------------------------------------------------
// Verify the key constants have the expected underlying string values.
// This is a documentation/regression test: if a constant is renamed it
// should be a deliberate change, not an accidental typo.
// ---------------------------------------------------------------------------

func TestKeyConstants_HaveExpectedStringValues(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key  contextKey
		want string
	}{
		{UserIDKey, "user_id"},
		{UserRoleKey, "user_role"},
		{CurrentUserKey, "current_user"},
		{JWTClaimsKey, "jwt_claims"},
		{AppIDKey, "app_id"},
		{RequestIDKey, "request_id"},
		{IPAddressKey, "ip_address"},
	}
	for _, c := range cases {
		if string(c.key) != c.want {
			t.Errorf("contextKey %q: underlying string = %q, want %q", c.want, string(c.key), c.want)
		}
	}
}
