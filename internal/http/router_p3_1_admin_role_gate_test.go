// Package http — regression tests for P3-1 / CRIT-01: the /api/admin router
// group had no authorisation gate. AuthMiddleware verified the token and put
// the user's role in the context, but nothing checked it, so any
// authenticated user (including a self-signup on any client) could reach
// every admin handler — create/reset superadmins, manage OAuth clients, drive
// SOC configuration. Scope gates are opt-in and any user may request
// scope=admin, so they were never an authorisation boundary.
//
// These tests drive the REAL admin router with real signed tokens and walk
// every registered /api/admin route:
//   - role=user       → 403 on every route (never reaches a handler)
//   - role=admin      → passes the group gate, 403 on /superadmins/*
//   - role=superadmin → passes both gates
//
// Handlers are nil: a request that is correctly rejected by middleware never
// reaches them, and a request that wrongly gets through would panic on the
// nil receiver — which the assertions below would also report as a failure.
package http

import (
	"context"
	"errors"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// p31UserRepo serves one fixed user for every FindByID; the embedded
// interface is nil so any other method call fails loudly.
type p31UserRepo struct {
	repository.UserRepository
	user *model.User
}

func (r *p31UserRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	if r.user == nil || r.user.ID != id {
		return nil, errors.New("user not found")
	}
	return r.user, nil
}

// p31UserService backs GET /api/admin/profile, the one handler exercised on
// the positive path.
type p31UserService struct {
	service.UserService
	user *model.User
}

func (s *p31UserService) GetByID(_ context.Context, id uint) (*model.User, error) {
	if s.user == nil || s.user.ID != id {
		return nil, errors.New("user not found")
	}
	return s.user, nil
}

func p31TokenService(t *testing.T) *auth.TokenService {
	t.Helper()
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "https://test.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		EmailTokenTTL:   time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  time.Hour,
	})
}

func p31Mint(t *testing.T, ts *auth.TokenService, user *model.User) string {
	t.Helper()
	app := &model.App{ID: 1, ClientID: "test-client"}
	set, err := ts.GenerateTokenSet(user, app, string(user.Role), "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	return set.AccessToken
}

// p31Router builds the real admin router for the given user. Every handler
// except AdminAuthHandler (needed for /profile) is nil.
func p31Router(t *testing.T, ts *auth.TokenService, user *model.User) nethttp.Handler {
	t.Helper()
	adminAuth := handler.NewAdminAuthHandler(nil, &p31UserService{user: user})
	return newAdminRouter(
		nil,       // adminHandler
		adminAuth, // adminAuthHandler
		nil,       // dashboardHandler
		nil,       // appUsersHandler
		nil,       // appLogsHandler
		nil,       // monitoringHandler
		nil,       // adminLogsHandler
		nil,       // settingsHandler
		nil,       // healthHandler
		nil,       // magicLinkHandler (nil-safe)
		ts,
		&p31UserRepo{user: user},
		nil, // usedTokenRepo (nil-safe in isRevoked)
		nil, // userAppRoleRepo
		nil, // appRepo
		RouterConfig{},
	)
}

// p31AdminRoutes enumerates every registered method+pattern under /api/admin,
// with path parameters substituted so the request actually matches.
func p31AdminRoutes(t *testing.T, h nethttp.Handler) [][2]string {
	t.Helper()
	mux, ok := h.(chi.Routes)
	if !ok {
		t.Fatalf("router is %T, want chi.Routes", h)
	}
	var routes [][2]string
	err := chi.Walk(mux, func(method, route string, _ nethttp.Handler, _ ...func(nethttp.Handler) nethttp.Handler) error {
		if !strings.HasPrefix(route, "/api/admin/") && route != "/api/admin" {
			return nil
		}
		// /api/admin/login is the public password login (registered outside the
		// protected group) — it is not part of this gate.
		if route == "/api/admin/login" {
			return nil
		}
		route = strings.ReplaceAll(route, "{id}", "1")
		route = strings.ReplaceAll(route, "{ip}", "203.0.113.9")
		route = strings.ReplaceAll(route, "/*", "")
		routes = append(routes, [2]string{method, route})
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	if len(routes) < 30 {
		t.Fatalf("only %d /api/admin routes enumerated — walk looks broken", len(routes))
	}
	return routes
}

func p31Do(h nethttp.Handler, method, path, token string) int {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestP31_PlainUser_Gets403OnEveryAdminRoute(t *testing.T) {
	ts := p31TokenService(t)
	user := &model.User{ID: 42, Email: "user@example.com", Role: model.UserRoleUser, IsVerified: true}
	h := p31Router(t, ts, user)
	tok := p31Mint(t, ts, user)

	for _, rt := range p31AdminRoutes(t, h) {
		if code := p31Do(h, rt[0], rt[1], tok); code != nethttp.StatusForbidden {
			t.Errorf("P3-1: role=user %s %s → %d, want 403", rt[0], rt[1], code)
		}
	}
}

func TestP31_Admin_PassesGroupGate_ButNotSuperadminRoutes(t *testing.T) {
	ts := p31TokenService(t)
	admin := &model.User{ID: 7, Email: "admin@example.com", Role: model.UserRoleAdmin, IsVerified: true}
	h := p31Router(t, ts, admin)
	tok := p31Mint(t, ts, admin)

	// Positive path: the group gate lets a global admin through to a handler.
	if code := p31Do(h, nethttp.MethodGet, "/api/admin/profile", tok); code != nethttp.StatusOK {
		t.Fatalf("role=admin GET /api/admin/profile → %d, want 200", code)
	}
	// Superadmin management is superadmin-only.
	for _, rt := range p31AdminRoutes(t, h) {
		if !strings.HasPrefix(rt[1], "/api/admin/superadmins") {
			continue
		}
		if code := p31Do(h, rt[0], rt[1], tok); code != nethttp.StatusForbidden {
			t.Errorf("P3-1: role=admin %s %s → %d, want 403", rt[0], rt[1], code)
		}
	}
}

func TestP31_Superadmin_PassesBothGates(t *testing.T) {
	ts := p31TokenService(t)
	sa := &model.User{ID: 1, Email: "root@example.com", Role: model.UserRoleSuperadmin, IsVerified: true}
	h := p31Router(t, ts, sa)
	tok := p31Mint(t, ts, sa)

	if code := p31Do(h, nethttp.MethodGet, "/api/admin/profile", tok); code != nethttp.StatusOK {
		t.Fatalf("role=superadmin GET /api/admin/profile → %d, want 200", code)
	}
	// The superadmin gate must not reject a superadmin. The handler behind
	// this route is nil in the harness, so anything other than 403 proves the
	// middleware chain admitted the request; the recovered nil-handler panic
	// surfaces as 500 here and is expected.
	if code := p31Do(h, nethttp.MethodGet, "/api/admin/superadmins/", tok); code == nethttp.StatusForbidden {
		t.Fatalf("role=superadmin GET /api/admin/superadmins/ → 403; the superadmin gate rejected a superadmin")
	}
}

func TestP31_NoToken_401(t *testing.T) {
	ts := p31TokenService(t)
	h := p31Router(t, ts, &model.User{ID: 1, Role: model.UserRoleSuperadmin})
	req := httptest.NewRequest(nethttp.MethodGet, "/api/admin/profile", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != nethttp.StatusUnauthorized {
		t.Fatalf("no token → %d, want 401", rr.Code)
	}
}
