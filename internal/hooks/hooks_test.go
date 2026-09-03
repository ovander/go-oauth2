package hooks

import (
	"context"
	"errors"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

func TestBeforeTokenIssue_FirstErrorVetoesAndWraps(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	var order []string
	OnBeforeTokenIssue(func(_ context.Context, e *TokenIssue) error { order = append(order, "a"); return nil })
	OnBeforeTokenIssue(func(_ context.Context, e *TokenIssue) error {
		order = append(order, "b")
		return errors.New("nope")
	})
	OnBeforeTokenIssue(func(_ context.Context, _ *TokenIssue) error { order = append(order, "c"); return nil })

	err := RunBeforeTokenIssue(context.Background(), &TokenIssue{Grant: "refresh_token"})
	if !errors.Is(err, ErrVetoed) {
		t.Fatalf("err = %v, want ErrVetoed", err)
	}
	if len(order) != 2 {
		t.Fatalf("hooks after the veto must not run: %v", order)
	}
}

func TestBeforeTokenIssue_PanicFailsClosed(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	OnBeforeTokenIssue(func(_ context.Context, _ *TokenIssue) error { panic("boom") })
	if err := RunBeforeTokenIssue(context.Background(), &TokenIssue{}); !errors.Is(err, ErrVetoed) {
		t.Fatalf("a panicking hook must veto, got %v", err)
	}
}

func TestBeforeTokenIssue_NoHooksAllows(t *testing.T) {
	Reset()
	if err := RunBeforeTokenIssue(context.Background(), &TokenIssue{}); err != nil {
		t.Fatal(err)
	}
}

func TestObservers_SeeEventsAndSurvivePanics(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	var logins, provisioned int
	OnAfterLogin(func(_ context.Context, _ Login) { panic("observer bug") })
	OnAfterLogin(func(_ context.Context, e Login) {
		if e.User != nil && e.User.ID == 7 && e.Method == "password" {
			logins++
		}
	})
	OnUserProvisioned(func(_ context.Context, e UserProvisioned) {
		if e.Source == "signup" {
			provisioned++
		}
	})
	RunAfterLogin(context.Background(), Login{User: &model.User{ID: 7}, Method: "password", MFA: true})
	RunUserProvisioned(context.Background(), UserProvisioned{User: &model.User{ID: 8}, Source: "signup"})
	if logins != 1 || provisioned != 1 {
		t.Fatalf("logins=%d provisioned=%d, want 1/1 (a panicking observer must not stop the others)", logins, provisioned)
	}
}
