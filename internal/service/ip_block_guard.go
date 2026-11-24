package service

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Errors returned by IPBlockGuard.Check.
var (
	// ErrInvalidBlockIP: the value is not an IP address.
	ErrInvalidBlockIP = errors.New("not an IP address")
	// ErrProtectedIP: the address must never be blocked.
	ErrProtectedIP = errors.New("this address cannot be blocked")
)

// IPBlockGuard says which addresses must never be blocked: loopback and
// unspecified addresses, the server's own addresses and every address in
// TRUSTED_PROXIES. Blocking one of them would cut off the consoles (they reach
// the admin API through a local proxy), and with them the route that lifts
// the block. Both the manual block route and the automatic defence consult
// it. A nil guard protects loopback and unspecified addresses only.
type IPBlockGuard struct {
	trusted []netip.Prefix
	own     map[netip.Addr]bool
}

// NewIPBlockGuard builds the guard from the trusted proxy ranges and the
// server's own addresses (see LocalAddrs).
func NewIPBlockGuard(trusted []*net.IPNet, own []netip.Addr) *IPBlockGuard {
	g := &IPBlockGuard{own: make(map[netip.Addr]bool, len(own))}
	for _, n := range trusted {
		if n == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		bits, _ := n.Mask.Size()
		addr = addr.Unmap()
		if addr.Is4() && bits > 32 {
			bits -= 96
		}
		if p, err := addr.Prefix(bits); err == nil {
			g.trusted = append(g.trusted, p)
		}
	}
	for _, a := range own {
		g.own[a.Unmap().WithZone("")] = true
	}
	return g
}

// LocalAddrs returns the addresses of the server's network interfaces; an
// error reading them yields none (loopback stays protected regardless).
func LocalAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if addr, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out
}

// Check parses ip and returns its canonical form (an IPv4-mapped IPv6 address
// as IPv4, no zone), the form the block list is matched against. It returns
// ErrInvalidBlockIP for a value that is not an address and ErrProtectedIP for
// an address that must never be blocked.
func (g *IPBlockGuard) Check(ip string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", ErrInvalidBlockIP
	}
	addr = addr.Unmap().WithZone("")
	switch {
	case addr.IsLoopback(), addr.IsUnspecified():
		return "", fmt.Errorf("%w: loopback or unspecified", ErrProtectedIP)
	case g != nil && g.own[addr]:
		return "", fmt.Errorf("%w: one of the server's own addresses", ErrProtectedIP)
	}
	if g != nil {
		for _, p := range g.trusted {
			if p.Contains(addr) {
				return "", fmt.Errorf("%w: a trusted proxy (TRUSTED_PROXIES)", ErrProtectedIP)
			}
		}
	}
	return addr.String(), nil
}
