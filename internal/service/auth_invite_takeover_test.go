package service_test

// An invite token is returned to whoever sent the invite (an app admin, or an
// app's service account), so accepting it must never change the password of an
// account that is already in use: it may only activate the account the invite
// created, and only with an invite of the app that created it.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
)

// inviteUserRepo holds one user by email and records writes.
type inviteUserRepo struct {
	repository.UserRepository
	user    *model.User
	updates int
	creates int
}

func (r *inviteUserRepo) FindByEmail(_ context.Context, email string) (*model.User, error) {
	if r.user != nil && r.user.Email == email {
		c := *r.user
		return &c, nil
	}
	return nil, errors.New("record not found")
}

// Update models the repository: it never writes the password or the token
// version.
func (r *inviteUserRepo) Update(_ context.Context, u *model.User) error {
	r.updates++
	c := *u
	if r.user != nil {
		c.HashedPassword, c.TokenVersion = r.user.HashedPassword, r.user.TokenVersion
	}
	r.user = &c
	return nil
}

// SetPassword models the repository: the hash, the verification and the
// token-version bump are one write.
func (r *inviteUserRepo) SetPassword(_ context.Context, id uint, change repository.PasswordChange) error {
	if r.user == nil || r.user.ID != id {
		return errors.New("record not found")
	}
	r.updates++
	r.user.HashedPassword = change.HashedPassword
	r.user.TokenVersion++
	if change.ConfirmedAt != nil {
		r.user.IsVerified = true
		r.user.ConfirmedAt = change.ConfirmedAt
	}
	if change.ChangedAt != nil {
		r.user.PasswordChangedAt = change.ChangedAt
	}
	return nil
}

func (r *inviteUserRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	if r.user == nil || r.user.ID != id {
		return nil, errors.New("record not found")
	}
	c := *r.user
	return &c, nil
}

func (r *inviteUserRepo) Create(_ context.Context, u *model.User) error {
	r.creates++
	u.ID = 1000
	c := *u
	r.user = &c
	return nil
}

// inviteRolesRepo returns a fixed list of roles for FindByUser (or an error).
type inviteRolesRepo struct {
	nilUserAppRoleRepo
	roles []model.UserAppRole
	err   error
	reads int
}

func (r *inviteRolesRepo) FindByUser(_ context.Context, _ uint) ([]model.UserAppRole, error) {
	r.reads++
	return r.roles, r.err
}

// inviteAuditRepo records the security events written.
type inviteAuditRepo struct {
	repository.SecurityAuditLogRepository
	events []*model.SecurityAuditLog
}

func (r *inviteAuditRepo) Create(_ context.Context, l *model.SecurityAuditLog) error {
	r.events = append(r.events, l)
	return nil
}

func acceptInviteFor(t *testing.T, existing *model.User) (*inviteUserRepo, *succeedOnceTokenRepo, error) {
	t.Helper()
	users, used, _, err := acceptAppInvite(t, existing, nil, 1)
	return users, used, err
}

// acceptAppInvite accepts an invite of app tokenApp for invitee@example.test,
// with existing as the account on file and roles as its app roles.
func acceptAppInvite(t *testing.T, existing *model.User, roles *inviteRolesRepo, tokenApp uint) (*inviteUserRepo, *succeedOnceTokenRepo, *inviteAuditRepo, error) {
	t.Helper()
	ts := testTokenService(t)
	users := &inviteUserRepo{user: existing}
	used := &succeedOnceTokenRepo{used: map[string]bool{}}
	audit := &inviteAuditRepo{}
	if roles == nil {
		roles = &inviteRolesRepo{}
	}
	svc := service.NewAuthServiceFull(users,
		&stubAppRepo{app: &model.App{ID: tokenApp, Name: "Some App", ClientID: "some"}},
		roles, used, audit, ts, nil, service.AuthServiceConfig{MaxFailedAttempts: 5})
	tok, err := ts.GenerateInviteToken("invitee@example.test", tokenApp, "user", 99)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.AcceptInvite(context.Background(), tok, "Invitee", "Invitee@Pass123!")
	return users, used, audit, err
}

func appID(id uint) *uint { return &id }

func TestAcceptInvite_NeverResetsAnActiveAccount(t *testing.T) {
	now := time.Now()
	for name, u := range map[string]*model.User{
		"verified":                     {ID: 7, Email: "invitee@example.test", HashedPassword: "own-hash", IsVerified: true, Source: "signup"},
		"signed in before":             {ID: 7, Email: "invitee@example.test", HashedPassword: "own-hash", LastLogin: &now, Source: "manual"},
		"confirmed":                    {ID: 7, Email: "invitee@example.test", HashedPassword: "own-hash", ConfirmedAt: &now, Source: "invite"},
		"own signup, not yet verified": {ID: 7, Email: "invitee@example.test", HashedPassword: "own-hash", Source: "signup"},
		"carried over":                 {ID: 7, Email: "invitee@example.test", HashedPassword: "own-hash", IsVerified: true, Source: "legacy"},
	} {
		t.Run(name, func(t *testing.T) {
			users, used, err := acceptInviteFor(t, u)
			if !errors.Is(err, service.ErrInviteAccountActive) {
				t.Fatalf("AcceptInvite err = %v, want ErrInviteAccountActive", err)
			}
			if users.user.HashedPassword != "own-hash" || users.updates != 0 || users.creates != 0 {
				t.Fatalf("the account was changed: hash %q, updates %d, creates %d",
					users.user.HashedPassword, users.updates, users.creates)
			}
			if len(used.used) != 0 {
				t.Error("a refused invite consumed the token")
			}
		})
	}
}

// The normal flow still works: the account an invite of app 1 created
// (throwaway password, never verified, never signed in) is activated with the
// user's password by an invite of app 1, and a brand-new address gets an
// account that records the app whose invite created it.
func TestAcceptInvite_ActivatesThePendingAccount(t *testing.T) {
	for _, source := range []string{"manual", "invite"} {
		users, _, err := acceptInviteFor(t, &model.User{ID: 7, Email: "invitee@example.test", HashedPassword: "throwaway", Source: source, InviteAppID: appID(1)})
		if err != nil {
			t.Fatalf("source %s: AcceptInvite err = %v", source, err)
		}
		if users.user.HashedPassword == "throwaway" || !users.user.IsVerified {
			t.Fatalf("source %s: pending account not activated: %+v", source, users.user)
		}
		// #366: choosing the first password retires the reset links issued
		// for the pending account before it.
		if users.user.PasswordChangedAt == nil {
			t.Fatalf("source %s: activation did not record the password change", source)
		}
	}
	users, _, err := acceptInviteFor(t, nil)
	if err != nil || users.creates != 1 {
		t.Fatalf("new address: err = %v, creates = %d", err, users.creates)
	}
	if users.user.InviteAppID == nil || *users.user.InviteAppID != 1 {
		t.Fatalf("new address: invite_app_id = %v, want 1", users.user.InviteAppID)
	}
}

// An invite only activates a pending account created for the same app. The
// app is the one recorded on the account; for an account that predates the
// record, the app of its oldest role; with no role, no app.
func TestAcceptInvite_OnlyActivatesAPendingAccountOfTheSameApp(t *testing.T) {
	const appA, appB = 1, 2
	pending := func(invitedBy *uint) *model.User {
		return &model.User{ID: 7, Email: "invitee@example.test", HashedPassword: "throwaway", Source: "manual", InviteAppID: invitedBy}
	}
	roles := func(rs ...model.UserAppRole) *inviteRolesRepo { return &inviteRolesRepo{roles: rs} }
	for _, tc := range []struct {
		name     string
		user     *model.User
		roles    *inviteRolesRepo
		tokenApp uint
		activate bool
	}{
		{"created for A, invite of A", pending(appID(appA)), roles(), appA, true},
		{"created for A, invite of B", pending(appID(appA)), roles(), appB, false},
		{"created for A, invite of B, B holds the oldest role", pending(appID(appA)),
			roles(model.UserAppRole{ID: 1, UserID: 7, AppID: appB}, model.UserAppRole{ID: 2, UserID: 7, AppID: appA}), appB, false},
		{"created by an invite of A, invite of B", &model.User{ID: 7, Email: "invitee@example.test", HashedPassword: "throwaway", Source: "invite", InviteAppID: appID(appA)}, roles(), appB, false},
		{"legacy, oldest role in A, invite of A", pending(nil),
			roles(model.UserAppRole{ID: 9, UserID: 7, AppID: appB}, model.UserAppRole{ID: 3, UserID: 7, AppID: appA}), appA, true},
		{"legacy, oldest role in A, invite of B", pending(nil),
			roles(model.UserAppRole{ID: 9, UserID: 7, AppID: appB}, model.UserAppRole{ID: 3, UserID: 7, AppID: appA}), appB, false},
		{"legacy, no role, invite of A", pending(nil), roles(), appA, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users, used, audit, err := acceptAppInvite(t, tc.user, tc.roles, tc.tokenApp)
			if tc.activate {
				if err != nil {
					t.Fatalf("AcceptInvite err = %v, want the account activated", err)
				}
				if users.user.HashedPassword == "throwaway" || !users.user.IsVerified {
					t.Fatalf("pending account not activated: %+v", users.user)
				}
				return
			}
			if !errors.Is(err, service.ErrInviteForOtherApp) {
				t.Fatalf("AcceptInvite err = %v, want ErrInviteForOtherApp", err)
			}
			if users.user.HashedPassword != "throwaway" || users.user.IsVerified || users.updates != 0 || users.creates != 0 {
				t.Fatalf("the account was changed: %+v, updates %d, creates %d", users.user, users.updates, users.creates)
			}
			if len(used.used) != 0 {
				t.Error("a refused invite consumed the token")
			}
			if len(audit.events) != 1 || audit.events[0].EventType != model.SecurityEventInviteAccepted ||
				audit.events[0].Success || audit.events[0].Details["reason"] != "invite_other_app" {
				t.Fatalf("security events = %+v, want one failed invite_accepted with reason invite_other_app", audit.events)
			}
			if tc.user.InviteAppID != nil && tc.roles.reads != 0 {
				t.Error("roles were read for an account that records its invite app")
			}
		})
	}
}

func TestInviteOwnerApp(t *testing.T) {
	u := &model.User{ID: 7}
	if _, ok := service.InviteOwnerApp(u, nil); ok {
		t.Error("an account with no recorded app and no role has an owner app")
	}
	// Roles of another user are ignored; the lowest id wins.
	got, ok := service.InviteOwnerApp(u, []model.UserAppRole{
		{ID: 1, UserID: 8, AppID: 5}, {ID: 4, UserID: 7, AppID: 3}, {ID: 2, UserID: 7, AppID: 2},
	})
	if !ok || got != 2 {
		t.Errorf("InviteOwnerApp = %d, %v; want 2, true", got, ok)
	}
	u.InviteAppID = appID(9)
	if got, ok := service.InviteOwnerApp(u, []model.UserAppRole{{ID: 1, UserID: 7, AppID: 2}}); !ok || got != 9 {
		t.Errorf("InviteOwnerApp = %d, %v; want the recorded app 9", got, ok)
	}
}

// When the roles of a legacy pending account cannot be read, the invite is not
// accepted, but it is not refused as another app's either: no invite_other_app
// event, the account and the token are left as they were, and the same invite
// succeeds once the roles can be read.
func TestAcceptInvite_RolesUnreadable_FailsClosedWithoutConsumingTheToken(t *testing.T) {
	ts := testTokenService(t)
	users := &inviteUserRepo{user: &model.User{ID: 7, Email: "invitee@example.test", HashedPassword: "throwaway", Source: "manual"}}
	used := &succeedOnceTokenRepo{used: map[string]bool{}}
	audit := &inviteAuditRepo{}
	roles := &inviteRolesRepo{err: errors.New("db down")}
	svc := service.NewAuthServiceFull(users, &stubAppRepo{app: &model.App{ID: 1, Name: "Some App", ClientID: "some"}},
		roles, used, audit, ts, nil, service.AuthServiceConfig{MaxFailedAttempts: 5})
	tok, err := ts.GenerateInviteToken("invitee@example.test", 1, "user", 99)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.AcceptInvite(context.Background(), tok, "Invitee", "Invitee@Pass123!")
	if err == nil || errors.Is(err, service.ErrInviteForOtherApp) || errors.Is(err, service.ErrInviteAccountActive) {
		t.Fatalf("AcceptInvite err = %v, want an internal error", err)
	}
	if users.user.HashedPassword != "throwaway" || users.updates != 0 || users.creates != 0 {
		t.Fatalf("the account was changed: %+v", users.user)
	}
	if len(audit.events) != 0 {
		t.Fatalf("security events = %+v, want none", audit.events)
	}
	if len(used.used) != 0 {
		t.Fatal("the token was consumed by a failed read")
	}

	// The store recovers: the oldest role is in app 1, so the same invite activates.
	roles.err = nil
	roles.roles = []model.UserAppRole{{ID: 1, UserID: 7, AppID: 1}}
	if _, err := svc.AcceptInvite(context.Background(), tok, "Invitee", "Invitee@Pass123!"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !users.user.IsVerified || users.user.HashedPassword == "throwaway" {
		t.Fatal("retry did not activate the account")
	}
}

// Activating a pending account moves its token version (the password is set
// with SetPassword); the tokens issued on acceptance carry the new version,
// so they are valid.
func TestAcceptInvite_TokensCarryTheNewTokenVersion(t *testing.T) {
	ts := testTokenService(t)
	users := &inviteUserRepo{user: &model.User{ID: 7, Email: "invitee@example.test", HashedPassword: "throwaway",
		Source: "manual", InviteAppID: appID(1), TokenVersion: 4}}
	svc := service.NewAuthServiceFull(users,
		&stubAppRepo{app: &model.App{ID: 1, Name: "Some App", ClientID: "some"}},
		&inviteRolesRepo{}, &succeedOnceTokenRepo{used: map[string]bool{}}, &inviteAuditRepo{}, ts, nil,
		service.AuthServiceConfig{MaxFailedAttempts: 5})
	tok, err := ts.GenerateInviteToken("invitee@example.test", 1, "user", 99)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.AcceptInvite(context.Background(), tok, "Invitee", "Invitee@Pass123!")
	if err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}
	if users.user.TokenVersion != 5 || users.user.HashedPassword == "throwaway" || !users.user.IsVerified {
		t.Fatalf("stored account: version %d, password changed %v, verified %v; want 5, true, true",
			users.user.TokenVersion, users.user.HashedPassword != "throwaway", users.user.IsVerified)
	}
	claims, err := ts.VerifyAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.TokenVersion != 5 {
		t.Fatalf("access token version %d, want 5 (the stored one)", claims.TokenVersion)
	}
}
