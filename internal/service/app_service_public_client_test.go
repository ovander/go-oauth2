// Package service — tests for public client support in AppService.Create.
//
// RFC 6749 §2.1 defines two client types:
//   - confidential: can securely maintain credentials (backend servers)
//   - public:       cannot keep a secret (SPAs, mobile apps)
//
// When IsPublic=true is passed to Create():
//   - no client_secret is generated or stored (ClientSecretHash must be "")
//   - RequirePKCE is automatically set to true regardless of the request field
//   - the IsPublic flag is persisted on the model
//
// The App.IsConfidential() helper is the canonical way to check whether a
// client must supply a secret at the token endpoint.
package service

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
)

// ---------------------------------------------------------------------------
// In-memory App repository for AppService unit tests
// ---------------------------------------------------------------------------

type memAppRepo struct {
	mu   sync.Mutex
	apps map[uint]*model.App
	next uint
}

func newMemAppRepo() *memAppRepo {
	return &memAppRepo{apps: make(map[uint]*model.App), next: 1}
}

func (r *memAppRepo) Create(_ context.Context, app *model.App) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	app.ID = r.next
	r.next++
	r.apps[app.ID] = app
	return nil
}

func (r *memAppRepo) FindByID(_ context.Context, id uint) (*model.App, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.apps[id]; ok {
		return a, nil
	}
	return nil, errors.New("not found")
}

func (r *memAppRepo) FindByClientID(_ context.Context, clientID string) (*model.App, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.apps {
		if a.ClientID == clientID {
			return a, nil
		}
	}
	return nil, errors.New("not found")
}

func (r *memAppRepo) FindAll(_ context.Context) ([]model.App, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]model.App, 0, len(r.apps))
	for _, a := range r.apps {
		out = append(out, *a)
	}
	return out, nil
}

func (r *memAppRepo) FindByOwnerID(_ context.Context, _ uint) ([]model.App, error) { return nil, nil }
func (r *memAppRepo) Update(_ context.Context, app *model.App) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.apps[app.ID] = app
	return nil
}
func (r *memAppRepo) Delete(_ context.Context, id uint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.apps, id)
	return nil
}
func (r *memAppRepo) GetAllRedirectURIs(_ context.Context) ([]string, error) { return nil, nil }

var _ repository.AppRepository = (*memAppRepo)(nil)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newAppSvc() *appService {
	return &appService{repo: newMemAppRepo()}
}

// ---------------------------------------------------------------------------
// App.IsConfidential — model helper
// ---------------------------------------------------------------------------

func TestApp_IsConfidential_ConfidentialClient(t *testing.T) {
	// A client with IsPublic=false and a non-empty secret hash is confidential.
	app := &model.App{IsPublic: false, ClientSecretHash: "bcrypt-hash"}
	if !app.IsConfidential() {
		t.Error("IsConfidential() = false for client with secret hash; want true")
	}
}

func TestApp_IsConfidential_PublicClient_EmptyHash(t *testing.T) {
	// A client with IsPublic=true has no secret hash and is not confidential.
	app := &model.App{IsPublic: true, ClientSecretHash: ""}
	if app.IsConfidential() {
		t.Error("IsConfidential() = true for public client; want false")
	}
}

func TestApp_IsConfidential_PublicFlag_TakesPrecedence(t *testing.T) {
	// If IsPublic=true but somehow a hash exists, IsConfidential must
	// still return false — IsPublic is the authoritative flag.
	app := &model.App{IsPublic: true, ClientSecretHash: "stale-hash"}
	if app.IsConfidential() {
		t.Error("IsConfidential() = true when IsPublic=true; IsPublic must take precedence")
	}
}

func TestApp_IsConfidential_NeitherFlagNorHash(t *testing.T) {
	// A legacy client with no hash and IsPublic=false has an empty
	// ClientSecretHash — IsConfidential() returns false (public by omission).
	app := &model.App{IsPublic: false, ClientSecretHash: ""}
	if app.IsConfidential() {
		t.Error("IsConfidential() = true for client with empty hash and IsPublic=false; want false")
	}
}

// ---------------------------------------------------------------------------
// AppService.Create — public client (IsPublic=true)
// ---------------------------------------------------------------------------

func TestCreate_PublicClient_NoSecretGenerated(t *testing.T) {
	// Public clients must never have a client secret.  ClientSecretHash must
	// be empty and the returned plaintext secret must also be empty.
	svc := newAppSvc()
	req := dto.CreateAppRequest{
		Name:         "My SPA",
		RedirectURIs: []string{"https://spa.example.com/cb"},
		IsPublic:     true,
	}

	app, secret, err := svc.Create(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if secret != "" {
		t.Errorf("Create() returned client_secret %q for public client; want empty string", secret)
	}
	if app.ClientSecretHash != "" {
		t.Errorf("Create() set ClientSecretHash = %q for public client; want empty string", app.ClientSecretHash)
	}
}

func TestCreate_PublicClient_IsPublicPersistedOnModel(t *testing.T) {
	svc := newAppSvc()
	req := dto.CreateAppRequest{
		Name:     "Public App",
		IsPublic: true,
	}

	app, _, err := svc.Create(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !app.IsPublic {
		t.Error("Create() did not set IsPublic=true on returned app")
	}
}

func TestCreate_PublicClient_RequirePKCEAutoEnabled(t *testing.T) {
	// When IsPublic=true, RequirePKCE must be set to true automatically —
	// even if the caller did not include require_pkce in the request.
	svc := newAppSvc()
	req := dto.CreateAppRequest{
		Name:        "SPA without explicit PKCE flag",
		IsPublic:    true,
		RequirePKCE: false, // not set by caller
	}

	app, _, err := svc.Create(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !app.RequirePKCE {
		t.Error("Create() did not auto-enable RequirePKCE for public client; want true")
	}
}

func TestCreate_PublicClient_ClientIDGenerated(t *testing.T) {
	// A public client still receives a generated client_id.
	svc := newAppSvc()
	req := dto.CreateAppRequest{Name: "SPA", IsPublic: true}

	app, _, err := svc.Create(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if app.ClientID == "" {
		t.Error("Create() returned empty ClientID for public client")
	}
}

// ---------------------------------------------------------------------------
// AppService.Create — confidential client (IsPublic=false, default)
// ---------------------------------------------------------------------------

func TestCreate_ConfidentialClient_SecretGenerated(t *testing.T) {
	// Confidential clients must receive a non-empty plaintext secret on
	// creation and have a non-empty hash stored.
	svc := newAppSvc()
	req := dto.CreateAppRequest{
		Name:         "Backend App",
		RedirectURIs: []string{"https://backend.example.com/cb"},
		IsPublic:     false,
	}

	app, secret, err := svc.Create(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if secret == "" {
		t.Error("Create() returned empty client_secret for confidential client")
	}
	if app.ClientSecretHash == "" {
		t.Error("Create() stored empty ClientSecretHash for confidential client")
	}
}

func TestCreate_ConfidentialClient_IsPublicFalse(t *testing.T) {
	svc := newAppSvc()
	req := dto.CreateAppRequest{Name: "Backend", IsPublic: false}

	app, _, err := svc.Create(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if app.IsPublic {
		t.Error("Create() set IsPublic=true for confidential client; want false")
	}
}

func TestCreate_ConfidentialClient_RequirePKCEFromRequest(t *testing.T) {
	// A confidential client can still opt into RequirePKCE explicitly.
	svc := newAppSvc()
	req := dto.CreateAppRequest{
		Name:        "Hybrid App",
		IsPublic:    false,
		RequirePKCE: true,
	}

	app, _, err := svc.Create(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !app.RequirePKCE {
		t.Error("Create() did not set RequirePKCE=true for confidential client that requested it")
	}
}

func TestCreate_ConfidentialClient_DefaultRequirePKCEFalse(t *testing.T) {
	// Confidential clients default to RequirePKCE=false.
	svc := newAppSvc()
	req := dto.CreateAppRequest{Name: "Backend", IsPublic: false}

	app, _, err := svc.Create(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if app.RequirePKCE {
		t.Error("Create() set RequirePKCE=true for confidential client without explicit flag; want false")
	}
}
