package service_test

// An invite token is returned to whoever sent the invite (an app admin, or an
// app's service account), so accepting it must never take over an account
// that is already in use: it may only activate the account the invite created.

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

func (r *inviteUserRepo) Update(_ context.Context, u *model.User) error {
	r.updates++
	c := *u
	r.user = &c
	return nil
}

func (r *inviteUserRepo) Create(_ context.Context, u *model.User) error {
	r.creates++
	u.ID = 1000
	c := *u
	r.user = &c
	return nil
}

func acceptInviteFor(t *testing.T, existing *model.User) (*inviteUserRepo, *succeedOnceTokenRepo, error) {
	t.Helper()
	ts := testTokenService(t)
	users := &inviteUserRepo{user: existing}
	used := &succeedOnceTokenRepo{used: map[string]bool{}}
	svc := service.NewAuthServiceWithUsedTokenRepo(users,
		&stubAppRepo{app: &model.App{ID: 1, Name: "Other App", ClientID: "other"}},
		&nilUserAppRoleRepo{}, used, ts, service.AuthServiceConfig{MaxFailedAttempts: 5})
	tok, err := ts.GenerateInviteToken("victim@example.test", 1, "user", 99)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.AcceptInvite(context.Background(), tok, "Attacker", "Attacker@Pass123!")
	return users, used, err
}

func TestAcceptInvite_NeverResetsAnActiveAccount(t *testing.T) {
	now := time.Now()
	for name, u := range map[string]*model.User{
		"verified":                     {ID: 7, Email: "victim@example.test", HashedPassword: "victim-hash", IsVerified: true, Source: "signup"},
		"signed in before":             {ID: 7, Email: "victim@example.test", HashedPassword: "victim-hash", LastLogin: &now, Source: "manual"},
		"confirmed":                    {ID: 7, Email: "victim@example.test", HashedPassword: "victim-hash", ConfirmedAt: &now, Source: "invite"},
		"own signup, not yet verified": {ID: 7, Email: "victim@example.test", HashedPassword: "victim-hash", Source: "signup"},
		"carried over":                 {ID: 7, Email: "victim@example.test", HashedPassword: "victim-hash", IsVerified: true, Source: "legacy"},
	} {
		t.Run(name, func(t *testing.T) {
			users, used, err := acceptInviteFor(t, u)
			if !errors.Is(err, service.ErrInviteAccountActive) {
				t.Fatalf("AcceptInvite err = %v, want ErrInviteAccountActive", err)
			}
			if users.user.HashedPassword != "victim-hash" || users.updates != 0 || users.creates != 0 {
				t.Fatalf("the account was changed: hash %q, updates %d, creates %d",
					users.user.HashedPassword, users.updates, users.creates)
			}
			if len(used.used) != 1 {
				t.Error("the token was not claimed before the account was looked up")
			}
		})
	}
}

// The normal flow still works: the account an invite created (throwaway
// password, never verified, never signed in) is activated with the user's
// password, and a brand-new address gets an account.
func TestAcceptInvite_ActivatesThePendingAccount(t *testing.T) {
	for _, source := range []string{"manual", "invite"} {
		users, _, err := acceptInviteFor(t, &model.User{ID: 7, Email: "victim@example.test", HashedPassword: "throwaway", Source: source})
		if err != nil {
			t.Fatalf("source %s: AcceptInvite err = %v", source, err)
		}
		if users.user.HashedPassword == "throwaway" || !users.user.IsVerified {
			t.Fatalf("source %s: pending account not activated: %+v", source, users.user)
		}
	}
	users, _, err := acceptInviteFor(t, nil)
	if err != nil || users.creates != 1 {
		t.Fatalf("new address: err = %v, creates = %d", err, users.creates)
	}
}
