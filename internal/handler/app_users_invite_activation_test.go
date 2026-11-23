package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// End to end against PostgreSQL: an invite only activates a pending account
// created for the same app. An app that adds a pending account created by
// another app's invite gets the role but no invite token and sends no email;
// an invite of that app is refused, and the original invite still activates
// the account. Run for both callers of the create endpoint: an app admin
// (POST /api/apps/{app_id}/users) and the app's service account
// (POST /api/apps/{app_id}/service/users).

// inviteMailRecorder records the invite emails sent.
type inviteMailRecorder struct {
	med03EmailService
	to []string
}

func (m *inviteMailRecorder) SendInviteEmail(to, _, _ string) error {
	m.to = append(m.to, to)
	return nil
}

type inviteEnv struct {
	tx      *gorm.DB
	ts      *auth.TokenService
	h       *AppUsersHandler
	authSvc service.AuthService
	mail    *inviteMailRecorder
	appA    model.App
	appB    model.App
	tag     string
}

func newInviteEnv(t *testing.T) *inviteEnv {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.App{}, &model.UserAppRole{}, &model.SecurityAuditLog{}, &model.UsedToken{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin: %v", tx.Error)
	}
	t.Cleanup(func() { tx.Rollback() })

	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour, InviteTokenTTL: time.Hour,
	})

	env := &inviteEnv{tx: tx, ts: ts, mail: &inviteMailRecorder{}, tag: fmt.Sprintf("%d", time.Now().UnixNano())}
	env.appA = model.App{Name: "invite-a", ClientID: "invite-a-" + env.tag, Active: true}
	env.appB = model.App{Name: "invite-b", ClientID: "invite-b-" + env.tag, Active: true}
	for _, a := range []*model.App{&env.appA, &env.appB} {
		if err := tx.Create(a).Error; err != nil {
			t.Fatalf("seed app: %v", err)
		}
	}

	userRepo := repository.NewUserRepository(tx)
	appRepo := repository.NewAppRepository(tx)
	roleRepo := repository.NewUserAppRoleRepository(tx)
	env.h = NewAppUsersHandler(service.NewUserService(userRepo), service.NewUserAppRoleService(roleRepo),
		service.NewAppService(appRepo), &noopAdminLogService{}, env.mail, ts, "https://auth.example.com")
	env.authSvc = service.NewAuthServiceFull(userRepo, appRepo, roleRepo, repository.NewUsedTokenRepository(tx),
		repository.NewSecurityAuditLogRepository(tx), ts, nil, service.AuthServiceConfig{MaxFailedAttempts: 5})
	return env
}

// add calls the create endpoint of app as an app admin or as the app's
// service account, and returns the status and decoded body.
func (e *inviteEnv) add(t *testing.T, caller string, app model.App, email, role string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": email, "role": role})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/apps/%d/users", app.ID)
	ctx := context.Background()
	if caller == "service account" {
		path = fmt.Sprintf("/api/apps/%d/service/users", app.ID)
		a := app
		ctx = context.WithValue(ctx, contextkeys.ServiceAccountAppKey, &a)
	} else {
		ctx = adminCtx(1, model.UserRoleUser)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("app_id", fmt.Sprint(app.ID))
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	e.h.CreateUser(rr, req)
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("POST %s → %d with a non-JSON body %q: %v", path, rr.Code, rr.Body.String(), err)
	}
	return rr.Code, out
}

func (e *inviteEnv) user(t *testing.T, email string) model.User {
	t.Helper()
	var u model.User
	if err := e.tx.Where("email = ?", email).First(&u).Error; err != nil {
		t.Fatalf("load %s: %v", email, err)
	}
	return u
}

func (e *inviteEnv) accept(token string) error {
	_, err := e.authSvc.AcceptInvite(context.Background(), token, "Invitee", "Invitee@Pass123!")
	return err
}

func (e *inviteEnv) mint(t *testing.T, email string, app model.App, role string) string {
	t.Helper()
	tok, err := e.ts.GenerateInviteToken(email, app.ID, role, 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var inviteCallers = []string{"app admin", "service account"}

func TestIntegration_InviteActivation_PendingAccountOfAnotherApp(t *testing.T) {
	for _, caller := range inviteCallers {
		t.Run(caller, func(t *testing.T) {
			e := newInviteEnv(t)
			email := "pending-" + e.tag + "@example.test"

			// App A invites a new address: a pending account recorded for A.
			code, resp := e.add(t, caller, e.appA, email, "user")
			tokA, _ := resp["invite_token"].(string)
			if code != http.StatusCreated || tokA == "" || resp["email_sent"] != true {
				t.Fatalf("A adds a new address: %d %v", code, resp)
			}
			u := e.user(t, email)
			if u.InviteAppID == nil || *u.InviteAppID != e.appA.ID || u.IsVerified {
				t.Fatalf("pending account: invite_app_id %v, verified %v; want %d, false", u.InviteAppID, u.IsVerified, e.appA.ID)
			}
			hashBefore := u.HashedPassword

			// App B adds the same address: role assigned, no token, no email.
			code, resp = e.add(t, caller, e.appB, email, "admin")
			if code != http.StatusCreated {
				t.Fatalf("B adds the pending address: %d %v", code, resp)
			}
			if _, has := resp["invite_token"]; has {
				t.Fatalf("B received an invite token for A's pending account: %v", resp)
			}
			if resp["email_sent"] != false || len(e.mail.to) != 1 {
				t.Fatalf("B sent an invite email: email_sent %v, emails %v", resp["email_sent"], e.mail.to)
			}
			var roleB model.UserAppRole
			if err := e.tx.Where("user_id = ? AND app_id = ?", u.ID, e.appB.ID).First(&roleB).Error; err != nil || roleB.Role != model.AppRoleAdmin {
				t.Fatalf("B's role not assigned: %+v (%v)", roleB, err)
			}

			// An invite of B does not activate the account.
			if err := e.accept(e.mint(t, email, e.appB, "admin")); !errors.Is(err, service.ErrInviteForOtherApp) {
				t.Fatalf("B's invite: err = %v, want ErrInviteForOtherApp", err)
			}
			if after := e.user(t, email); after.HashedPassword != hashBefore || after.IsVerified || after.ConfirmedAt != nil {
				t.Fatal("B's invite changed the pending account")
			}
			var events int64
			e.tx.Model(&model.SecurityAuditLog{}).
				Where("event_type = ? AND user_id = ? AND app_id = ? AND success = false", model.SecurityEventInviteAccepted, u.ID, e.appB.ID).
				Count(&events)
			if events != 1 {
				t.Fatalf("refused invite audited %d times, want 1", events)
			}

			// A's original invite still activates it.
			if err := e.accept(tokA); err != nil {
				t.Fatalf("A's invite: %v", err)
			}
			if after := e.user(t, email); after.HashedPassword == hashBefore || !after.IsVerified {
				t.Fatal("A's invite did not activate the account")
			}
		})
	}
}

// An account in use keeps the existing behaviour: the role is assigned and a
// token returned, which never changes the account's password.
func TestIntegration_InviteActivation_ActiveAccountUnchanged(t *testing.T) {
	for _, caller := range inviteCallers {
		t.Run(caller, func(t *testing.T) {
			e := newInviteEnv(t)
			email := "active-" + e.tag + "@example.test"
			now := time.Now()
			active := model.User{Email: email, Name: "Active", HashedPassword: "own-hash", IsVerified: true, ConfirmedAt: &now, Source: "signup", Role: model.UserRoleUser}
			if err := e.tx.Create(&active).Error; err != nil {
				t.Fatal(err)
			}
			code, resp := e.add(t, caller, e.appB, email, "viewer")
			tok, _ := resp["invite_token"].(string)
			if code != http.StatusCreated || tok == "" || resp["email_sent"] != true || len(e.mail.to) != 1 {
				t.Fatalf("B adds an active account: %d %v, emails %v", code, resp, e.mail.to)
			}
			if err := e.accept(tok); !errors.Is(err, service.ErrInviteAccountActive) {
				t.Fatalf("accept: err = %v, want ErrInviteAccountActive", err)
			}
			if e.user(t, email).HashedPassword != "own-hash" {
				t.Fatal("the active account's password changed")
			}
		})
	}
}

// A pending account created before invite_app_id existed: the app of its
// oldest role may activate it, no other app; with no role, no app.
func TestIntegration_InviteActivation_LegacyPendingAccount(t *testing.T) {
	for _, caller := range inviteCallers {
		t.Run(caller, func(t *testing.T) {
			e := newInviteEnv(t)
			legacy := func(email string) model.User {
				u := model.User{Email: email, Name: email, HashedPassword: "throwaway", Source: "manual", Role: model.UserRoleUser}
				if err := e.tx.Create(&u).Error; err != nil {
					t.Fatal(err)
				}
				return u
			}

			email := "legacy-" + e.tag + "@example.test"
			u := legacy(email)
			if err := e.tx.Create(&model.UserAppRole{UserID: u.ID, AppID: e.appA.ID, Role: model.AppRoleUser}).Error; err != nil {
				t.Fatal(err)
			}
			code, resp := e.add(t, caller, e.appB, email, "admin")
			if _, has := resp["invite_token"]; code != http.StatusCreated || has || len(e.mail.to) != 0 {
				t.Fatalf("B adds A's legacy pending account: %d %v, emails %v", code, resp, e.mail.to)
			}
			if err := e.accept(e.mint(t, email, e.appB, "admin")); !errors.Is(err, service.ErrInviteForOtherApp) {
				t.Fatalf("B's invite: err = %v, want ErrInviteForOtherApp", err)
			}
			if err := e.accept(e.mint(t, email, e.appA, "user")); err != nil {
				t.Fatalf("A's invite: %v", err)
			}
			if !e.user(t, email).IsVerified {
				t.Fatal("A's invite did not activate the legacy account")
			}

			noRole := "legacy-norole-" + e.tag + "@example.test"
			legacy(noRole)
			if err := e.accept(e.mint(t, noRole, e.appA, "user")); !errors.Is(err, service.ErrInviteForOtherApp) {
				t.Fatalf("invite for a legacy account with no role: err = %v, want ErrInviteForOtherApp", err)
			}
			if e.user(t, noRole).HashedPassword != "throwaway" {
				t.Fatal("the legacy account with no role was changed")
			}
		})
	}
}

// A pending account that no app may activate (no recorded app, no role, e.g.
// created by an administrator) is claimed by the first app that adds it: that
// app's invite is issued and activates it; an app adding it afterwards gets
// the role but no invite.
func TestIntegration_InviteActivation_UnclaimedPendingAccountIsClaimed(t *testing.T) {
	for _, caller := range inviteCallers {
		t.Run(caller, func(t *testing.T) {
			e := newInviteEnv(t)
			email := "unclaimed-" + e.tag + "@example.test"
			u := model.User{Email: email, Name: email, HashedPassword: "throwaway", Source: "manual", Role: model.UserRoleUser}
			if err := e.tx.Create(&u).Error; err != nil {
				t.Fatal(err)
			}

			code, resp := e.add(t, caller, e.appB, email, "user")
			tokB, _ := resp["invite_token"].(string)
			if code != http.StatusCreated || tokB == "" || len(e.mail.to) != 1 || e.mail.to[0] != email {
				t.Fatalf("B adds the unclaimed account: %d %v, emails %v", code, resp, e.mail.to)
			}
			if got := e.user(t, email).InviteAppID; got == nil || *got != e.appB.ID {
				t.Fatalf("invite_app_id = %v, want %d", got, e.appB.ID)
			}

			code, resp = e.add(t, caller, e.appA, email, "admin")
			if _, has := resp["invite_token"]; code != http.StatusCreated || has || len(e.mail.to) != 1 {
				t.Fatalf("A adds B's account: %d %v, emails %v", code, resp, e.mail.to)
			}
			if err := e.accept(e.mint(t, email, e.appA, "admin")); !errors.Is(err, service.ErrInviteForOtherApp) {
				t.Fatalf("A's invite: err = %v, want ErrInviteForOtherApp", err)
			}
			if err := e.accept(tokB); err != nil {
				t.Fatalf("B's invite: %v", err)
			}
			if !e.user(t, email).IsVerified {
				t.Fatal("B's invite did not activate the account")
			}
		})
	}
}

// ClaimInviteApp sets invite_app_id only while it is NULL.
func TestIntegration_ClaimInviteApp_OnlyWhenUnset(t *testing.T) {
	e := newInviteEnv(t)
	u := model.User{Email: "claim-" + e.tag + "@example.test", Name: "Claim", HashedPassword: "x", Source: "manual", Role: model.UserRoleUser}
	if err := e.tx.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	repo := repository.NewUserRepository(e.tx)
	ctx := context.Background()
	if ok, err := repo.ClaimInviteApp(ctx, u.ID, e.appB.ID); err != nil || !ok {
		t.Fatalf("first claim: %v, %v; want true", ok, err)
	}
	if ok, err := repo.ClaimInviteApp(ctx, u.ID, e.appA.ID); err != nil || ok {
		t.Fatalf("second claim: %v, %v; want false", ok, err)
	}
	if got := e.user(t, u.Email).InviteAppID; got == nil || *got != e.appB.ID {
		t.Fatalf("invite_app_id = %v, want %d", got, e.appB.ID)
	}
}

// The app that created a pending account can invite it again (after removing
// it), and the new invite activates it.
func TestIntegration_InviteActivation_ReinviteBySameApp(t *testing.T) {
	for _, caller := range inviteCallers {
		t.Run(caller, func(t *testing.T) {
			e := newInviteEnv(t)
			email := "reinvite-" + e.tag + "@example.test"
			code, resp := e.add(t, caller, e.appA, email, "user")
			if first, _ := resp["invite_token"].(string); code != http.StatusCreated || first == "" || len(e.mail.to) != 1 || e.mail.to[0] != email {
				t.Fatalf("first invite: %d %v, emails %v", code, resp, e.mail.to)
			}
			u := e.user(t, email)
			if err := service.NewUserAppRoleService(repository.NewUserAppRoleRepository(e.tx)).RemoveRole(context.Background(), u.ID, e.appA.ID); err != nil {
				t.Fatal(err)
			}
			code, resp = e.add(t, caller, e.appA, email, "editor")
			tok, _ := resp["invite_token"].(string)
			if code != http.StatusCreated || tok == "" || len(e.mail.to) != 2 || e.mail.to[1] != email {
				t.Fatalf("re-invite: %d %v, emails %v", code, resp, e.mail.to)
			}
			if err := e.accept(tok); err != nil {
				t.Fatalf("accept the re-invite: %v", err)
			}
			if !e.user(t, email).IsVerified {
				t.Fatal("the re-invite did not activate the account")
			}
		})
	}
}

// rolesErrUserAppRoleService fails to read a user's roles; any write panics.
type rolesErrUserAppRoleService struct{ panicUserAppRoleService }

func (rolesErrUserAppRoleService) GetUserRoles(_ context.Context, _ uint) ([]model.UserAppRole, error) {
	return nil, errors.New("db down")
}

// Fail closed: when the roles of an existing pending account cannot be read,
// the request fails before any role is assigned or invite issued.
func TestCreateAppUser_PendingAccountRolesUnreadable_FailsClosed(t *testing.T) {
	us := &appUsersTestUserService{getByEmail: func(_ context.Context, email string) (*model.User, error) {
		return &model.User{ID: 5, Email: email, Role: model.UserRoleUser, Source: "manual"}, nil
	}}
	h := NewAppUsersHandler(us, &rolesErrUserAppRoleService{}, &panicAppService{}, &noopAdminLogService{}, nil, nil, "https://auth.example.com")
	rr := httptest.NewRecorder()
	h.CreateUser(rr, appUsersRequest(1, 1, `{"email":"pending@example.test","role":"admin"}`))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("CreateUser → %d %s, want 500", rr.Code, rr.Body.String())
	}
}

// claimRaceUserService loses the claim: another app recorded itself first.
type claimRaceUserService struct {
	appUsersTestUserService
	winner uint
}

func (s *claimRaceUserService) ClaimInviteApp(_ context.Context, _, _ uint) (bool, error) {
	return false, nil
}

func (s *claimRaceUserService) GetByID(_ context.Context, id uint) (*model.User, error) {
	w := s.winner
	return &model.User{ID: id, Source: "manual", InviteAppID: &w}, nil
}

// noRolesUserAppRoleService reports no role; any write panics.
type noRolesUserAppRoleService struct{ panicUserAppRoleService }

func (noRolesUserAppRoleService) GetUserRoles(_ context.Context, _ uint) ([]model.UserAppRole, error) {
	return nil, nil
}

// When another app claims an unclaimed pending account first, the account is
// read again and only the app that claimed it may issue an invite.
func TestPendingAccountInvite_LostClaimRereads(t *testing.T) {
	for _, tc := range []struct {
		name   string
		winner uint
		want   bool
	}{
		{"claimed by another app", 2, false},
		{"claimed by this app", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &AppUsersHandler{userService: &claimRaceUserService{winner: tc.winner}, userAppRoleService: &noRolesUserAppRoleService{}}
			got, err := h.pendingAccountInvite(context.Background(), &model.User{ID: 5, Source: "manual"}, 1)
			if err != nil || got != tc.want {
				t.Fatalf("pendingAccountInvite = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
