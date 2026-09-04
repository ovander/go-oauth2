package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dialViaClient exercises the guarded transport's DialContext exactly as a real
// request would, without needing a reachable server.
func dialViaClient(t *testing.T, addr string) error {
	t.Helper()
	c := NewHTTPClient(2 * time.Second)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("NewHTTPClient no longer uses *http.Transport")
	}
	conn, err := tr.DialContext(context.Background(), "tcp", addr)
	if conn != nil {
		_ = conn.Close()
	}
	return err
}

// The whole point of the connect-time check: an address that is private is
// refused at dial, whatever the URL said at registration.
func TestGuardedDial_RefusesPrivateLiterals(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:8081",        // the admin API
		"10.0.0.5:443",          // RFC 1918
		"192.168.1.1:443",       // RFC 1918
		"169.254.169.254:80",    // cloud metadata
		"[::1]:8081",            // IPv6 loopback
		"[::ffff:127.0.0.1]:80", // IPv4-mapped loopback
	} {
		err := dialViaClient(t, addr)
		if !errors.Is(err, ErrPrivateAddr) {
			t.Errorf("dial(%s) = %v, want ErrPrivateAddr", addr, err)
		}
	}
}

// A hostname whose answer is private is refused too — this is the DNS-rebinding
// case, where registration saw a public address and the connection would not.
func TestGuardedDial_RefusesPrivateResolution(t *testing.T) {
	original := Resolver
	Resolver = func(host string) ([]net.IP, error) {
		switch host {
		case "rebound.test":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		case "mixed.test":
			return []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("192.168.0.1")}, nil
		default:
			return nil, errors.New("no such host")
		}
	}
	t.Cleanup(func() { Resolver = original })

	for _, host := range []string{"rebound.test:443", "mixed.test:443"} {
		err := dialViaClient(t, host)
		if !errors.Is(err, ErrPrivateAddr) {
			t.Errorf("dial(%s) = %v, want ErrPrivateAddr", host, err)
		}
	}

	if err := dialViaClient(t, "nothing.test:443"); !errors.Is(err, ErrUnresolvable) {
		t.Errorf("dial(unresolvable) = %v, want ErrUnresolvable", err)
	}
}

// A public answer is dialled — and dialled at the address that was checked, so
// there is no window for the answer to change between check and connect.
func TestGuardedDial_AllowsPublicResolution(t *testing.T) {
	original := Resolver
	Resolver = func(h string) ([]net.IP, error) {
		if h == "public.test" {
			return []net.IP{net.ParseIP("203.0.113.1")}, nil // TEST-NET-3
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { Resolver = original })

	// Nothing is listening on 203.0.113.1, so the dial fails — but it must fail
	// as a connection error, never as a guard refusal. That distinction is the
	// assertion: the guard let a public answer through.
	err := dialViaClient(t, "public.test:443")
	if errors.Is(err, ErrPrivateAddr) || errors.Is(err, ErrUnresolvable) {
		t.Fatalf("a public answer was refused by the guard: %v", err)
	}
}

// Redirects are refused, so a public URL cannot bounce a request to a private
// address after the check has passed.
func TestNewHTTPClient_RefusesRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:8081/api/admin/apps", http.StatusFound)
	}))
	defer target.Close()

	c := NewHTTPClient(2 * time.Second)
	// Bypass only the address guard so the redirect policy is what is tested.
	if tr, ok := c.Transport.(*http.Transport); ok {
		plain := &net.Dialer{Timeout: 2 * time.Second}
		tr.DialContext = plain.DialContext
	}

	resp, err := c.Get(target.URL) //nolint:noctx // exercising the client's redirect policy
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("the redirect was followed")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error = %v, want a redirect refusal", err)
	}
}

// Connection reuse is off, so no request rides a connection validated for an
// earlier one, and proxy environment variables are never honoured for these
// operator-supplied targets.
func TestNewHTTPClient_TransportHardening(t *testing.T) {
	c := NewHTTPClient(3 * time.Second)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected an *http.Transport")
	}
	if !tr.DisableKeepAlives {
		t.Error("keep-alives are enabled; a later request could reuse a connection validated for an earlier one")
	}
	if tr.Proxy != nil {
		t.Error("a proxy is configured; webhook targets must not be routed through one")
	}
	if c.Timeout != 3*time.Second {
		t.Errorf("client timeout = %v, want 3s", c.Timeout)
	}
	if NewHTTPClient(0).Timeout != DefaultTimeout {
		t.Errorf("a zero timeout should fall back to %v", DefaultTimeout)
	}
}
