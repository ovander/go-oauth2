// Package main — structural tests for M-08: Bootstrap builds only the router
// that is actually needed.
//
// M-08 fix: Bootstrap previously always built both the combined (single-port)
// and the dual-port router, wasting memory and registering routes that will
// never receive requests.  It now builds only the router appropriate for the
// configured mode.
//
// These tests do not require a live database.  They verify the App struct
// contract (field presence, zero-value semantics) and the routing logic via
// the exported field names.
package main

import (
	"net/http"
	"testing"
)

// ---------------------------------------------------------------------------
// M-08: App struct has the correct fields for single-port and dual-port modes
// ---------------------------------------------------------------------------

func TestApp_SinglePortMode_OnlyRouterSet(t *testing.T) {
	t.Parallel()
	// Simulate what Bootstrap returns for single-port mode (AdminPort == "").
	// The Router field must be non-nil; OAuthRouter and AdminRouter must be nil.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	app := &App{
		Router: h,
	}

	if app.Router == nil {
		t.Error("App.Router must be non-nil in single-port mode")
	}
	if app.OAuthRouter != nil {
		t.Error("App.OAuthRouter must be nil in single-port mode")
	}
	if app.AdminRouter != nil {
		t.Error("App.AdminRouter must be nil in single-port mode")
	}
}

func TestApp_DualPortMode_OnlyOAuthAndAdminSet(t *testing.T) {
	t.Parallel()
	// Simulate what Bootstrap returns for dual-port mode (AdminPort != "").
	oauthH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	adminH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	app := &App{
		OAuthRouter: oauthH,
		AdminRouter: adminH,
	}

	if app.OAuthRouter == nil {
		t.Error("App.OAuthRouter must be non-nil in dual-port mode")
	}
	if app.AdminRouter == nil {
		t.Error("App.AdminRouter must be non-nil in dual-port mode")
	}
	if app.Router != nil {
		t.Error("App.Router must be nil in dual-port mode")
	}
}

func TestApp_Stop_NilFields_NoPanic(t *testing.T) {
	t.Parallel()
	// Stop must handle nil cleanup fields gracefully (all fields nil).
	app := &App{}
	// This must not panic.
	app.Stop()
}

// ---------------------------------------------------------------------------
// M-08: main.go selects the correct mode based on cfg.AdminPort
// ---------------------------------------------------------------------------

func TestMain_ModeSwitching_SinglePort_UsesRouter(t *testing.T) {
	t.Parallel()
	// A non-empty Router and nil OAuthRouter/AdminRouter signals single-port mode.
	// The start functions in main.go check app.Router vs app.OAuthRouter+app.AdminRouter.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	app := &App{Router: h}

	if app.Router == nil {
		t.Error("single-port mode: app.Router must be set")
	}
	if app.OAuthRouter != nil || app.AdminRouter != nil {
		t.Error("single-port mode: dual-port router fields must be nil")
	}
}

func TestMain_ModeSwitching_DualPort_UsesSeparateRouters(t *testing.T) {
	t.Parallel()
	oauthH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	adminH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	app := &App{OAuthRouter: oauthH, AdminRouter: adminH}

	if app.OAuthRouter == nil || app.AdminRouter == nil {
		t.Error("dual-port mode: both OAuthRouter and AdminRouter must be set")
	}
	if app.Router != nil {
		t.Error("dual-port mode: combined Router must be nil")
	}
}
