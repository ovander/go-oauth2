package ssrf

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestParseURL_StaticRules(t *testing.T) {
	valid := []string{
		"https://hooks.example.com/socrate",
		"https://hooks.example.com:8443/path?x=1",
		"HTTPS://hooks.example.com/",
	}
	for _, raw := range valid {
		if _, err := ParseURL(raw); err != nil {
			t.Errorf("ParseURL(%q): unexpected error %v", raw, err)
		}
	}

	cases := map[string]error{
		"":                             ErrNoHost,
		"   ":                          ErrNoHost,
		"http://hooks.example.com/":    ErrNotHTTPS,
		"ftp://hooks.example.com/":     ErrNotHTTPS,
		"file:///etc/passwd":           ErrNotHTTPS,
		"https://user:pw@hooks.test/":  ErrHasUserinfo,
		"https://hooks.test/path#frag": ErrHasFragment,
		"https:///just-a-path":         ErrNoHost,
		"https://" + strings.Repeat("a", MaxURLLength) + ".test/": nil, // length, not a sentinel
	}
	for raw, want := range cases {
		_, err := ParseURL(raw)
		if err == nil {
			t.Errorf("ParseURL(%q): expected an error", raw)
			continue
		}
		if want != nil && !errors.Is(err, want) {
			t.Errorf("ParseURL(%q) = %v, want %v", raw, err, want)
		}
	}
}

// The addresses an SSRF payload actually reaches for: loopback, the cloud
// metadata endpoint, RFC 1918, and their IPv6 disguises.
func TestIsPublicIP(t *testing.T) {
	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
		"2606:4700:4700::1111",
	}
	for _, s := range public {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = false, want true", s)
		}
	}

	private := []string{
		"127.0.0.1",          // loopback — the admin API lives here
		"127.1.2.3",          // the rest of 127/8
		"0.0.0.0",            // unspecified
		"0.1.2.3",            // "this network"
		"10.0.0.5",           // RFC 1918
		"172.16.4.1",         // RFC 1918
		"192.168.1.1",        // RFC 1918
		"169.254.169.254",    // cloud metadata
		"100.64.0.1",         // RFC 6598 CGNAT
		"224.0.0.1",          // multicast
		"240.0.0.1",          // reserved
		"255.255.255.255",    // broadcast
		"::1",                // IPv6 loopback
		"::",                 // IPv6 unspecified
		"fe80::1",            // IPv6 link-local
		"fc00::1",            // IPv6 unique-local
		"fd12:3456::1",       // IPv6 unique-local
		"ff02::1",            // IPv6 multicast
		"2001:db8::1",        // documentation
		"::ffff:127.0.0.1",   // IPv4-mapped loopback
		"::ffff:10.0.0.1",    // IPv4-mapped RFC 1918
		"64:ff9b::7f00:1",    // NAT64-embedded 127.0.0.1
		"64:ff9b::a9fe:a9fe", // NAT64-embedded 169.254.169.254
	}
	for _, s := range private {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q is not an IP", s)
		}
		if IsPublicIP(ip) {
			t.Errorf("IsPublicIP(%s) = true, want false", s)
		}
	}

	if IsPublicIP(nil) {
		t.Error("IsPublicIP(nil) = true, want false")
	}
}

// CheckHost short-circuits on IP literals without touching the resolver, so the
// obvious SSRF targets are refused with no DNS in the picture.
func TestCheckHost_IPLiterals(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"} {
		if err := CheckHost(host); !errors.Is(err, ErrPrivateAddr) {
			t.Errorf("CheckHost(%s) = %v, want ErrPrivateAddr", host, err)
		}
	}
	if err := CheckHost("8.8.8.8"); err != nil {
		t.Errorf("CheckHost(8.8.8.8) = %v, want nil", err)
	}
	if err := CheckHost(""); !errors.Is(err, ErrNoHost) {
		t.Errorf("CheckHost(\"\") = %v, want ErrNoHost", err)
	}
}

// A hostname that cannot resolve is refused rather than accepted optimistically.
func TestCheckHost_Unresolvable(t *testing.T) {
	err := CheckHost("this-host-does-not-exist.invalid")
	if !errors.Is(err, ErrUnresolvable) {
		t.Errorf("CheckHost(.invalid) = %v, want ErrUnresolvable", err)
	}
}

// localhost resolves to loopback, so a URL naming it is refused end to end.
func TestValidateURL_RefusesLocalhost(t *testing.T) {
	if _, err := ValidateURL("https://localhost:8081/api/admin/apps"); err == nil {
		t.Fatal("https://localhost was accepted; the admin API is reachable there")
	}
	if _, err := ValidateURL("https://127.0.0.1/x"); !errors.Is(err, ErrPrivateAddr) {
		t.Fatal("loopback literal was accepted")
	}
}
