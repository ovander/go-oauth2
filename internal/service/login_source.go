package service

import (
	"context"
	"net/netip"

	"github.com/ovander/go-oauth2/internal/contextkeys"
)

// loginSourceUnknown is the source of a sign-in whose client address is not
// known: such attempts share one count, so they cannot escape it.
const loginSourceUnknown = "unknown"

// loginSource is the source a failed sign-in is counted against
// (LOCKOUT_SOURCE_MODE, #403): the client's IPv4 address, or the /64 of its
// IPv6 address (one subscriber's allocation, which they can rotate within).
// The address is the one the request middleware resolved, trusted-proxy aware.
func loginSource(ctx context.Context) string {
	raw, _ := ctx.Value(contextkeys.IPAddressKey).(string)
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return loginSourceUnknown
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.WithZone("").Prefix(64)
	if err != nil {
		return loginSourceUnknown
	}
	return prefix.String()
}
