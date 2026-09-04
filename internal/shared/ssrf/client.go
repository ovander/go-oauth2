package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// DefaultTimeout bounds a whole outbound request. A webhook target that hangs
// must not hold a dispatcher worker.
const DefaultTimeout = 5 * time.Second

// ErrRedirect is returned when a target answers with a redirect. Following one
// would re-open every hole the URL check closed: a public URL can redirect to
// `http://127.0.0.1:8081/`, and the redirected request is issued by the client,
// not by anything that re-validated it.
var ErrRedirect = fmt.Errorf("webhook target attempted a redirect; redirects are not followed")

// NewHTTPClient builds an HTTP client for calling operator-supplied URLs.
//
// The important part is DialContext: validation at registration time is not
// enough on its own, because DNS can change between then and now — a target
// that resolved to a public address an hour ago can resolve to 127.0.0.1 today
// (DNS rebinding). So every connection is checked against the address actually
// being dialled, after resolution, immediately before the socket is opened.
// There is no window between the check and the connect for the answer to change.
func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}

	transport := &http.Transport{
		DialContext:           guardedDial(dialer),
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		// Connection reuse would let a later request ride a connection whose
		// address was validated for an earlier one. Cheap to disable, and it
		// keeps every request's check honest.
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		Proxy:             nil, // never honour proxy env vars for these calls
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return ErrRedirect
		},
	}
}

// guardedDial wraps a dialer so the resolved address is vetted before connecting.
func guardedDial(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("webhook dial: cannot parse address %q: %w", addr, err)
		}

		// An IP literal needs no resolution — check it and dial it.
		if ip := net.ParseIP(host); ip != nil {
			if !IsPublicIP(ip) {
				return nil, fmt.Errorf("%w: refusing to connect to %s", ErrPrivateAddr, ip)
			}
			return dialer.DialContext(ctx, network, addr)
		}

		ips, err := Resolver(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnresolvable, host)
		}

		// Dial the first address that is public, by IP rather than by name, so
		// the connection goes to the address we checked. Resolving again inside
		// the dialer would reopen the very gap this closes.
		var lastErr error
		for _, ip := range ips {
			if !IsPublicIP(ip) {
				lastErr = fmt.Errorf("%w: %s resolves to %s", ErrPrivateAddr, host, ip)
				continue
			}
			conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("%w: %s", ErrPrivateAddr, host)
		}
		return nil, lastErr
	}
}
