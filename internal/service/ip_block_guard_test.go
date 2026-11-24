package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestIPBlockGuard_Check(t *testing.T) {
	_, proxies, _ := net.ParseCIDR("10.0.0.0/8")
	_, proxy6, _ := net.ParseCIDR("fd00::/8")
	g := NewIPBlockGuard([]*net.IPNet{proxies, proxy6}, []netip.Addr{netip.MustParseAddr("203.0.113.7")})

	for _, tc := range []struct {
		ip        string
		canonical string
		err       error
	}{
		{"198.51.100.9", "198.51.100.9", nil},
		{"::ffff:198.51.100.9", "198.51.100.9", nil},
		{"2001:db8::1", "2001:db8::1", nil},
		{"127.0.0.1", "", ErrProtectedIP},
		{"127.5.5.5", "", ErrProtectedIP},
		{"::1", "", ErrProtectedIP},
		{"::ffff:127.0.0.1", "", ErrProtectedIP},
		{"0.0.0.0", "", ErrProtectedIP},
		{"::", "", ErrProtectedIP},
		{"10.1.2.3", "", ErrProtectedIP},
		{"::ffff:10.1.2.3", "", ErrProtectedIP},
		{"fd12::5", "", ErrProtectedIP},
		{"203.0.113.7", "", ErrProtectedIP},
		{"not-an-ip", "", ErrInvalidBlockIP},
		{"198.51.100.0/24", "", ErrInvalidBlockIP},
		{"", "", ErrInvalidBlockIP},
	} {
		got, err := g.Check(tc.ip)
		if !errors.Is(err, tc.err) || got != tc.canonical {
			t.Errorf("Check(%q) = %q, %v; want %q, %v", tc.ip, got, err, tc.canonical, tc.err)
		}
	}
}

// Without a configured guard, loopback and unspecified addresses are still
// protected; anything else may be blocked.
func TestIPBlockGuard_NilProtectsLoopback(t *testing.T) {
	var g *IPBlockGuard
	if _, err := g.Check("127.0.0.1"); !errors.Is(err, ErrProtectedIP) {
		t.Errorf("nil guard, loopback: %v", err)
	}
	if got, err := g.Check("10.1.2.3"); err != nil || got != "10.1.2.3" {
		t.Errorf("nil guard, 10.1.2.3: %q, %v", got, err)
	}
}

// The automatic defence never blocks a protected address: repeated failed
// logins from loopback or a trusted proxy (a proxy not configured as
// trusted would attribute every request to it) create no block, while the
// same failures from an ordinary address do.
func TestAutoDefense_NeverBlocksAProtectedAddress(t *testing.T) {
	svc, repo := newTestAutoDefense()
	defer svc.Stop()
	_, proxies, _ := net.ParseCIDR("10.0.0.0/8")
	svc.SetIPBlockGuard(NewIPBlockGuard([]*net.IPNet{proxies}, nil))

	for _, ip := range []string{"127.0.0.1", "::1", "10.0.0.5"} {
		for i := 0; i < 20; i++ {
			svc.RecordFailedLogin(context.Background(), ip, "test-agent")
		}
	}
	if repo.creates != 0 {
		t.Fatalf("%d block(s) created for protected addresses", repo.creates)
	}
	for i := 0; i < 20; i++ {
		svc.RecordFailedLogin(context.Background(), "198.51.100.9", "test-agent")
	}
	if repo.creates == 0 {
		t.Fatal("an ordinary address was not blocked: the test does not reach the blocking path")
	}
}

// A skipped block resets the address's attempts, as a block does, so a burst
// of failures from a protected address keeps a bounded list.
func TestAutoDefense_SkippedBlockResetsAttempts(t *testing.T) {
	svc, _ := newTestAutoDefense()
	defer svc.Stop()
	for i := 0; i < 500; i++ {
		svc.RecordFailedLogin(context.Background(), "127.0.0.1", "test-agent")
	}
	svc.mu.RLock()
	n := len(svc.ipRecords["127.0.0.1"].FailedAttempts)
	svc.mu.RUnlock()
	if n >= svc.config.FailedLoginThreshold {
		t.Fatalf("%d attempts kept for a protected address, want fewer than the threshold (%d)", n, svc.config.FailedLoginThreshold)
	}
}
