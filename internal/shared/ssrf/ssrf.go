// Package ssrf holds the outbound-request guard used wherever Socrate is asked
// to call a URL an operator supplied — today, webhook delivery (A3).
//
// The threat is concrete: Socrate runs its admin API on loopback `:8081` and
// sits on a VPS alongside other services. A webhook target of
// `http://127.0.0.1:8081/api/admin/...` or `http://169.254.169.254/` would turn
// the delivery worker into a confused deputy with the server's own network
// position. So a target must be HTTPS, must not carry credentials, and must
// resolve only to public addresses — checked at registration *and* re-checked
// at connect time, because DNS can change in between (a DNS-rebinding attack
// against a target that validated cleanly an hour ago).
package ssrf

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Guard errors. They are deliberately specific: an operator typing a webhook
// URL into the console needs to know *why* it was refused.
var (
	ErrNotHTTPS     = errors.New("webhook URL must use https")
	ErrHasUserinfo  = errors.New("webhook URL must not contain credentials")
	ErrHasFragment  = errors.New("webhook URL must not contain a fragment")
	ErrNoHost       = errors.New("webhook URL must have a host")
	ErrPrivateAddr  = errors.New("webhook URL resolves to a non-public address")
	ErrUnresolvable = errors.New("webhook URL host does not resolve")
)

// MaxURLLength bounds a stored target URL.
const MaxURLLength = 2000

// Resolver resolves a hostname to its addresses. It is a package variable so
// tests can run hermetically (no DNS), and so a deployment could substitute a
// resolver later. Production always uses net.LookupIP.
var Resolver = net.LookupIP

// ValidateURL parses and vets an operator-supplied target URL. It enforces the
// static rules (scheme, no userinfo, host present) and then resolves the host,
// refusing the target if *any* returned address is non-public — one private
// answer in a round-robin set is enough to make the target unsafe.
//
// Resolution failures are reported as ErrUnresolvable rather than silently
// accepted: a target that cannot be reached is a configuration error worth
// surfacing at registration time.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := ParseURL(raw)
	if err != nil {
		return nil, err
	}
	if err := CheckHost(u.Hostname()); err != nil {
		return nil, err
	}
	return u, nil
}

// ParseURL applies the static (no-DNS) rules. It is separated from CheckHost so
// tests — and callers that only want syntax checking — need no resolver.
func ParseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrNoHost
	}
	if len(raw) > MaxURLLength {
		return nil, fmt.Errorf("webhook URL exceeds %d characters", MaxURLLength)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("webhook URL is not a valid URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, ErrNotHTTPS
	}
	if u.User != nil {
		return nil, ErrHasUserinfo
	}
	if u.Fragment != "" {
		return nil, ErrHasFragment
	}
	if u.Hostname() == "" {
		return nil, ErrNoHost
	}
	return u, nil
}

// CheckHost resolves host and reports an error unless every address it resolves
// to is public. A host that is already an IP literal is checked directly.
func CheckHost(host string) error {
	if host == "" {
		return ErrNoHost
	}

	if ip := net.ParseIP(host); ip != nil {
		if !IsPublicIP(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateAddr, ip)
		}
		return nil
	}

	addrs, err := Resolver(host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("%w: %s", ErrUnresolvable, host)
	}
	for _, ip := range addrs {
		if !IsPublicIP(ip) {
			return fmt.Errorf("%w: %s resolves to %s", ErrPrivateAddr, host, ip)
		}
	}
	return nil
}

// IsPublicIP reports whether ip is a globally routable unicast address that is
// safe to connect to from the server.
//
// Refused: loopback, RFC 1918 / RFC 4193 private ranges, link-local (which
// covers the 169.254.169.254 cloud metadata endpoint), unspecified, multicast,
// interface-local, the RFC 6598 carrier-grade NAT range, and IPv4-mapped or
// NAT64 IPv6 forms of any of the above — an attacker who cannot use
// `127.0.0.1` will happily try `::ffff:127.0.0.1` or `64:ff9b::7f00:1`.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Collapse an IPv4-mapped IPv6 address to its IPv4 form so the IPv4 rules
	// below actually apply to it.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else if isNAT64(ip) {
		return IsPublicIP(nat64Embedded(ip))
	}

	switch {
	case ip.IsUnspecified(),
		ip.IsLoopback(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast():
		return false
	}

	if v4 := ip.To4(); v4 != nil {
		// RFC 6598 carrier-grade NAT: 100.64.0.0/10.
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return false
		}
		// RFC 1122 "this network": 0.0.0.0/8.
		if v4[0] == 0 {
			return false
		}
		// RFC 6890 reserved / benchmarking / documentation ranges are not
		// routable either; 240.0.0.0/4 covers the reserved block.
		if v4[0] >= 240 {
			return false
		}
		return true
	}

	// IPv6: refuse the unique-local (fc00::/7) and documentation (2001:db8::/32)
	// blocks. IsPrivate already covers fc00::/7, so this is the documentation
	// block plus anything not global unicast.
	if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}
	return ip.IsGlobalUnicast()
}

// nat64Prefix is the RFC 6052 well-known prefix 64:ff9b::/96, which embeds an
// IPv4 address in its low 32 bits.
var nat64Prefix = []byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}

func isNAT64(ip net.IP) bool {
	if len(ip) != net.IPv6len {
		return false
	}
	for i, b := range nat64Prefix {
		if ip[i] != b {
			return false
		}
	}
	return true
}

func nat64Embedded(ip net.IP) net.IP {
	return net.IPv4(ip[12], ip[13], ip[14], ip[15])
}
