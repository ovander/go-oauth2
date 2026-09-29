package service

import (
	"context"
	"fmt"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// adminClientStore is the narrow slice of the app repository that admin-console
// seeding needs; the full repository.AppRepository satisfies it.
type adminClientStore interface {
	FindByClientID(ctx context.Context, clientID string) (*model.App, error)
	Create(ctx context.Context, app *model.App) error
}

// EnsureAdminConsoleClient idempotently registers the first-party admin-console
// OAuth client as a **public, PKCE-mandatory** client with the exact-match
// redirect URIs from config and no secret. It is a no-op when clientID or
// redirectURIs are empty (feature disabled) or when the client already exists —
// so it is safe to call on every startup.
//
// Returns true when a new client was created. Existing clients are left
// untouched (an operator can manage their redirect URIs via the admin API);
// this never weakens an existing client to public/secretless.
func EnsureAdminConsoleClient(ctx context.Context, store adminClientStore, clientID string, redirectURIs []string) (bool, error) {
	if clientID == "" || len(redirectURIs) == 0 {
		return false, nil
	}

	if existing, err := store.FindByClientID(ctx, clientID); err == nil && existing != nil {
		logger.FromContext(ctx).Infof("admin console client %q already registered; leaving as-is", clientID)
		return false, nil
	}

	app := &model.App{
		Name:         "Admin Console",
		ClientID:     clientID,
		RedirectURIs: redirectURIs,
		IsPublic:     true, // no client secret
		RequirePKCE:  true, // S256 enforced (also implied by IsPublic)
		Active:       true,
	}
	if err := store.Create(ctx, app); err != nil {
		return false, fmt.Errorf("seed admin console client %q: %w", clientID, err)
	}
	logger.FromContext(ctx).Infof("registered first-party admin console client %q (public, PKCE) with %d redirect URI(s)", clientID, len(redirectURIs))
	return true, nil
}
