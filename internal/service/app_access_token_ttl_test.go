package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
)

// A per-client access-token lifetime is validated on create and update; on
// update, omitted keeps it and 0 clears it.
func TestAppService_AccessTokenTTL(t *testing.T) {
	ctx := context.Background()
	svc := newAppSvc()
	secs := func(v int) *int { return &v }
	redirects := []string{"https://app.example.com/callback"}

	for _, bad := range []int{0, 59, 86401, -1} {
		if _, _, err := svc.Create(ctx, dto.CreateAppRequest{Name: "bad", RedirectURIs: redirects, AccessTokenTTLSeconds: secs(bad)}, 1); !errors.Is(err, ErrInvalidAccessTokenTTL) {
			t.Errorf("Create(ttl=%d) err = %v, want ErrInvalidAccessTokenTTL", bad, err)
		}
	}

	app, _, err := svc.Create(ctx, dto.CreateAppRequest{Name: "svc", RedirectURIs: redirects, AccessTokenTTLSeconds: secs(300)}, 1)
	if err != nil || app.AccessTokenTTLSeconds == nil || *app.AccessTokenTTLSeconds != 300 {
		t.Fatalf("Create(ttl=300) = %v, %v", app, err)
	}

	name := "renamed"
	if got, err := svc.Update(ctx, app.ID, dto.UpdateAppRequest{Name: &name}); err != nil || got.AccessTokenTTLSeconds == nil || *got.AccessTokenTTLSeconds != 300 {
		t.Fatalf("Update(omitted) changed the lifetime: %v, %v", got.AccessTokenTTLSeconds, err)
	}
	if _, err := svc.Update(ctx, app.ID, dto.UpdateAppRequest{AccessTokenTTLSeconds: secs(30)}); !errors.Is(err, ErrInvalidAccessTokenTTL) {
		t.Errorf("Update(ttl=30) err = %v, want ErrInvalidAccessTokenTTL", err)
	}
	if got, err := svc.Update(ctx, app.ID, dto.UpdateAppRequest{AccessTokenTTLSeconds: secs(600)}); err != nil || *got.AccessTokenTTLSeconds != 600 {
		t.Fatalf("Update(ttl=600) = %v, %v", got.AccessTokenTTLSeconds, err)
	}
	if got, err := svc.Update(ctx, app.ID, dto.UpdateAppRequest{AccessTokenTTLSeconds: secs(0)}); err != nil || got.AccessTokenTTLSeconds != nil {
		t.Fatalf("Update(ttl=0) = %v, %v; want cleared", got.AccessTokenTTLSeconds, err)
	}
}
