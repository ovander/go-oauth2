package policy_test

import (
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/policy"
)

func TestUnmetObligation(t *testing.T) {
	now := time.Now()
	recent, old := now.Add(-time.Minute).Unix(), now.Add(-time.Hour).Unix()
	mfa := []string{"pwd", "otp", "mfa"}
	cases := []struct {
		name        string
		obligations []string
		amr         []string
		authTime    int64
		window      time.Duration
		want        string
	}{
		{"none", nil, nil, 0, 5 * time.Minute, ""},
		{"mfa met", []string{policy.ObligationMFA}, mfa, recent, 5 * time.Minute, ""},
		{"mfa: password only", []string{policy.ObligationMFA}, []string{"pwd"}, recent, 5 * time.Minute, policy.ObligationMFA},
		{"mfa: no token", []string{policy.ObligationMFA}, nil, 0, 5 * time.Minute, policy.ObligationMFA},
		{"fresh met", []string{policy.ObligationFreshAuth}, mfa, recent, 5 * time.Minute, ""},
		{"fresh: too old", []string{policy.ObligationFreshAuth}, mfa, old, 5 * time.Minute, policy.ObligationFreshAuth},
		{"fresh: no auth_time", []string{policy.ObligationFreshAuth}, mfa, 0, 5 * time.Minute, policy.ObligationFreshAuth},
		{"fresh: window disabled", []string{policy.ObligationFreshAuth}, nil, old, 0, ""},
		{"first unmet wins", []string{policy.ObligationFreshAuth, policy.ObligationMFA}, []string{"pwd"}, old, 5 * time.Minute, policy.ObligationFreshAuth},
		{"unknown is unmet", []string{"require_hardware_key"}, mfa, recent, 5 * time.Minute, "require_hardware_key"},
	}
	for _, c := range cases {
		if got := policy.UnmetObligation(c.obligations, c.amr, c.authTime, c.window, now); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
