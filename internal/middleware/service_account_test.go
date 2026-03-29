// Package middleware — unit tests for ServiceAccountMiddleware.
//
// Tests verify:
//  1. Missing Authorization header → 401
//  2. Malformed Authorization header (no "Bearer " prefix) → 401
//  3. Expired token → 401
//  4. Token with user sub (not "app:…") → 403
//  5. Token app ID does not match route {app_id} → 403
//  6. App not found in repository → 401
//  7. App is inactive → 403
//  8. Valid token + matching app_id + active app → 200, app stored in context
//  9. GetServiceAccountAppFromContext returns nil for empty / wrong-type context
package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

type stubAppRepo struct {
	findByID func(ctx context.Context, id uint) (*model.App, error)
}

func (r *stubAppRepo) FindByID(ctx context.Context, id uint) (*model.App, error) {
	return r.findByID(ctx, id)
}
func (r *stubAppRepo) Create(_ context.Context, _ *model.App) error { panic("not implemented") }
func (r *stubAppRepo) Update(_ context.Context, _ *model.App) error { panic("not implemented") }
func (r *stubAppRepo) Delete(_ context.Context, _ uint) error       { panic("not implemented") }
func (r *stubAppRepo) FindByClientID(_ context.Context, _ string) (*model.App, error) {
	panic("not implemented")
}
func (r *stubAppRepo) FindAll(_ context.Context) ([]model.App, error) {
	panic("not implemented")
}
func (r *stubAppRepo) FindByOwnerID(_ context.Context, _ uint) ([]model.App, error) {
	panic("not implemented")
}
func (r *stubAppRepo) Count(_ context.Context) (int64, error)              { panic("not implemented") }
func (r *stubAppRepo) GetAllRedirectURIs(_ context.Context) ([]string, error) { panic("not implemented") }

var _ repository.AppRepository = (*stubAppRepo)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type testTokenBundle struct {
	ts *auth.TokenService
	km *auth.KeyManager
}

// newTestBundle creates a TokenService + KeyManager backed by a temp directory.
func newTestBundle(t *testing.T) testTokenBundle {
	t.Helper()
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "https://auth.example.com",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		EmailTokenTTL:   time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  time.Hour,
	})
	return testTokenBundle{ts: ts, km: km}
}

// makeServiceToken produces a valid client_credentials token for the given app.
func makeServiceToken(t *testing.T, b testTokenBundle, app *model.App) string {
	t.Helper()
	token, err := b.ts.GenerateClientCredentialsToken(app, "api")
	if err != nil {
		t.Fatalf("GenerateClientCredentialsToken: %v", err)
	}
	return token
}

// makeUserToken produces a valid user access token (sub = numeric user ID).
func makeUserToken(t *testing.T, b testTokenBundle, userID uint) string {
	t.Helper()
	user := &model.User{ID: userID, Email: "user@example.com", TokenVersion: 0}
	app := &model.App{ID: 1, ClientID: "test-client"}
	set, err := b.ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	return set.AccessToken
}

// makeExpiredServiceToken signs a service account JWT with a past expiry using
// the bundle's private key directly, bypassing the TTL in TokenService.
func makeExpiredServiceToken(t *testing.T, b testTokenBundle, appID uint) string {
	t.Helper()
	claims := auth.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "app:1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
		Scope: "api",
		Type:  "access",
	}
	_ = appID
	raw := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	raw.Header["kid"] = b.km.GetKeyID()
	tokenStr, err := raw.SignedString(b.km.GetPrivateKey())
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}
	return tokenStr
}

// saRequest builds a POST request with a chi route context and optional Bearer token.
func saRequest(appIDParam string, token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/apps/"+appIDParam+"/service/users", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("app_id", appIDParam)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// okHandler records that it was called and returns 200.
func okHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestServiceAccountMiddleware_MissingHeader(t *testing.T) {
	b := newTestBundle(t)
	mw := ServiceAccountMiddleware(&stubAppRepo{}, b.ts)

	called := false
	rr := httptest.NewRecorder()
	mw(okHandler(&called)).ServeHTTP(rr, saRequest("1", ""))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	if called {
		t.Error("next handler must not be called on missing header")
	}
}

func TestServiceAccountMiddleware_MalformedHeader(t *testing.T) {
	b := newTestBundle(t)
	mw := ServiceAccountMiddleware(&stubAppRepo{}, b.ts)

	req := saRequest("1", "")
	req.Header.Set("Authorization", "Token abc123") // not "Bearer …"

	called := false
	rr := httptest.NewRecorder()
	mw(okHandler(&called)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestServiceAccountMiddleware_ExpiredToken(t *testing.T) {
	b := newTestBundle(t)
	mw := ServiceAccountMiddleware(&stubAppRepo{}, b.ts)

	token := makeExpiredServiceToken(t, b, 1)
	called := false
	rr := httptest.NewRecorder()
	mw(okHandler(&called)).ServeHTTP(rr, saRequest("1", token))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", rr.Code)
	}
}

func TestServiceAccountMiddleware_UserTokenRejected(t *testing.T) {
	b := newTestBundle(t)
	// User token has sub = "42" (numeric) — not "app:…"
	userToken := makeUserToken(t, b, 42)
	mw := ServiceAccountMiddleware(&stubAppRepo{}, b.ts)

	called := false
	rr := httptest.NewRecorder()
	mw(okHandler(&called)).ServeHTTP(rr, saRequest("1", userToken))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for user token, got %d", rr.Code)
	}
}

func TestServiceAccountMiddleware_AppIDMismatch(t *testing.T) {
	b := newTestBundle(t)
	// Token is for app 2, but route says app_id=1
	app := &model.App{ID: 2, ClientID: "client-2", Active: true}
	token := makeServiceToken(t, b, app)
	mw := ServiceAccountMiddleware(&stubAppRepo{}, b.ts)

	called := false
	rr := httptest.NewRecorder()
	mw(okHandler(&called)).ServeHTTP(rr, saRequest("1", token))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for app ID mismatch, got %d", rr.Code)
	}
}

func TestServiceAccountMiddleware_AppNotFound(t *testing.T) {
	b := newTestBundle(t)
	app := &model.App{ID: 1, ClientID: "client-1", Active: true}
	token := makeServiceToken(t, b, app)

	repo := &stubAppRepo{
		findByID: func(_ context.Context, _ uint) (*model.App, error) {
			return nil, errors.New("not found")
		},
	}
	mw := ServiceAccountMiddleware(repo, b.ts)

	called := false
	rr := httptest.NewRecorder()
	mw(okHandler(&called)).ServeHTTP(rr, saRequest("1", token))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when app not found, got %d", rr.Code)
	}
}

func TestServiceAccountMiddleware_InactiveApp(t *testing.T) {
	b := newTestBundle(t)
	app := &model.App{ID: 1, ClientID: "client-1", Active: true}
	token := makeServiceToken(t, b, app)

	repo := &stubAppRepo{
		findByID: func(_ context.Context, _ uint) (*model.App, error) {
			return &model.App{ID: 1, Active: false}, nil // inactive in DB
		},
	}
	mw := ServiceAccountMiddleware(repo, b.ts)

	called := false
	rr := httptest.NewRecorder()
	mw(okHandler(&called)).ServeHTTP(rr, saRequest("1", token))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for inactive app, got %d", rr.Code)
	}
}

func TestServiceAccountMiddleware_ValidToken_StoresAppInContext(t *testing.T) {
	b := newTestBundle(t)
	activeApp := &model.App{ID: 1, ClientID: "client-1", Active: true}
	token := makeServiceToken(t, b, activeApp)

	repo := &stubAppRepo{
		findByID: func(_ context.Context, id uint) (*model.App, error) {
			if id == 1 {
				return activeApp, nil
			}
			return nil, errors.New("not found")
		},
	}
	mw := ServiceAccountMiddleware(repo, b.ts)

	var appFromCtx *model.App
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appFromCtx, _ = GetServiceAccountAppFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, saRequest("1", token))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if appFromCtx == nil {
		t.Fatal("expected *model.App in context, got nil")
	}
	if appFromCtx.ID != 1 {
		t.Errorf("expected app ID 1 in context, got %d", appFromCtx.ID)
	}
}

func TestGetServiceAccountAppFromContext_EmptyContext(t *testing.T) {
	app, ok := GetServiceAccountAppFromContext(context.Background())
	if ok || app != nil {
		t.Error("expected nil, false for empty context")
	}
}

func TestGetServiceAccountAppFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.ServiceAccountAppKey, "not-an-app")
	app, ok := GetServiceAccountAppFromContext(ctx)
	if ok || app != nil {
		t.Error("expected nil, false for wrong type stored in context")
	}
}
