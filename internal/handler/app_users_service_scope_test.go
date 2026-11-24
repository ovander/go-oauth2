package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
)

// seedUser stores an account; inviteApp is the app it was created for (nil:
// signed up on its own). memberOf gives it a role in those apps.
func (e *inviteEnv) seedUser(t *testing.T, email string, inviteApp *uint, memberOf ...model.App) model.User {
	t.Helper()
	now := time.Now()
	u := model.User{Email: email, Name: "Seeded", HashedPassword: "x", Role: model.UserRoleUser, Source: "signup",
		IsVerified: true, ConfirmedAt: &now, LastLogin: &now, InviteAppID: inviteApp}
	if err := e.tx.Create(&u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	for _, a := range memberOf {
		if err := e.tx.Create(&model.UserAppRole{UserID: u.ID, AppID: a.ID, Role: model.AppRoleUser}).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	return u
}

// patchProfile calls the service PATCH of app on user as the app's service
// account.
func (e *inviteEnv) patchProfile(app model.App, userID uint, body string) int {
	a := app
	ctx := context.WithValue(context.Background(), contextkeys.ServiceAccountAppKey, &a)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("app_id", fmt.Sprint(app.ID))
	rctx.URLParams.Add("user_id", fmt.Sprint(userID))
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/apps/%d/service/users/%d", app.ID, userID),
		bytes.NewBufferString(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	e.h.UpdateUserProfile(rr, req)
	return rr.Code
}

func (e *inviteEnv) hasRole(t *testing.T, userID uint, app model.App) bool {
	t.Helper()
	var n int64
	if err := e.tx.Model(&model.UserAppRole{}).Where("user_id = ? AND app_id = ?", userID, app.ID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// Under enforce, a service account adds a new address or an account created
// for its app, but not someone else's existing account (409, no role, a
// refusal audited); an app admin still can. Observe allows and audits; off
// is unchanged.
func TestIntegration_ServiceUserScope_AddExistingAccount(t *testing.T) {
	for _, mode := range []string{"off", "observe", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			e := newInviteEnv(t)
			audit := &captureAuditService{}
			e.h.SetServiceUserScope(mode, audit)
			other := e.seedUser(t, "someone-"+e.tag+"@example.test", nil)

			code, _ := e.add(t, "service account", e.appA, other.Email, "user")
			wantCode, wantRole := http.StatusCreated, true
			if mode == "enforce" {
				wantCode, wantRole = http.StatusConflict, false
			}
			if code != wantCode || e.hasRole(t, other.ID, e.appA) != wantRole {
				t.Fatalf("service account adds an existing account: %d, role %v; want %d, %v", code, e.hasRole(t, other.ID, e.appA), wantCode, wantRole)
			}
			ev := findEvent(audit, model.SecurityEventServiceUserScope)
			switch {
			case mode == "off" && ev != nil:
				t.Fatalf("off recorded an event: %+v", ev)
			case mode != "off" && (ev == nil || ev.Success != (mode == "observe") || ev.Details["action"] != "add_existing_account"):
				t.Fatalf("%s: event %+v", mode, ev)
			}

			// A new address, and an existing account created for this app
			// (not yet a member), are always accepted.
			if code, resp := e.add(t, "service account", e.appA, "fresh-"+e.tag+"@example.test", "user"); code != http.StatusCreated {
				t.Fatalf("new address: %d %v", code, resp)
			}
			ownApp := e.appA.ID
			created := e.seedUser(t, "created-"+e.tag+"@example.test", &ownApp)
			if code, resp := e.add(t, "service account", e.appA, created.Email, "user"); code != http.StatusCreated {
				t.Fatalf("account created for the app: %d %v", code, resp)
			}
			// An app admin adds the existing account whatever the mode.
			if code, resp := e.add(t, "app admin", e.appB, other.Email, "user"); code != http.StatusCreated {
				t.Fatalf("app admin adds an existing account: %d %v", code, resp)
			}
		})
	}
}

// An account already a member of the app is not an enrolment: it gets the
// existing "already has a role" answer, not account_exists, and no event.
func TestIntegration_ServiceUserScope_ExistingMemberIsNotAnEnrolment(t *testing.T) {
	e := newInviteEnv(t)
	audit := &captureAuditService{}
	e.h.SetServiceUserScope("enforce", audit)
	member := e.seedUser(t, "member-"+e.tag+"@example.test", nil, e.appA)
	code, resp := e.add(t, "service account", e.appA, member.Email, "user")
	if msg, _ := resp["error"].(string); code != http.StatusConflict || strings.HasPrefix(msg, "account_exists") {
		t.Fatalf("existing member: %d %v, want the existing 409 for a member", code, resp)
	}
	if ev := findEvent(audit, model.SecurityEventServiceUserScope); ev != nil {
		t.Fatalf("an existing member was recorded: %+v", ev)
	}
}

// Under enforce, a service account edits the profile of an account created
// for its app, but not of another member (403, unchanged); observe allows.
func TestIntegration_ServiceUserScope_EditProfile(t *testing.T) {
	for _, mode := range []string{"off", "observe", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			e := newInviteEnv(t)
			audit := &captureAuditService{}
			e.h.SetServiceUserScope(mode, audit)
			own := e.seedUser(t, "own-"+e.tag+"@example.test", &e.appA.ID, e.appA)
			foreign := e.seedUser(t, "foreign-"+e.tag+"@example.test", &e.appB.ID, e.appA, e.appB)

			if code := e.patchProfile(e.appA, own.ID, `{"name":"Renamed"}`); code != http.StatusOK {
				t.Fatalf("own account: %d", code)
			}
			want := http.StatusOK
			if mode == "enforce" {
				want = http.StatusForbidden
			}
			if code := e.patchProfile(e.appA, foreign.ID, `{"name":"Hijacked"}`); code != want {
				t.Fatalf("account created for another app: %d, want %d", code, want)
			}
			if mode == "enforce" && e.user(t, foreign.Email).Name != "Seeded" {
				t.Fatal("a refused edit changed the profile")
			}
			ev := findEvent(audit, model.SecurityEventServiceUserScope)
			if (mode == "off") != (ev == nil) || (ev != nil && ev.Details["action"] != "edit_profile") {
				t.Fatalf("%s: event %+v", mode, ev)
			}
		})
	}
}
