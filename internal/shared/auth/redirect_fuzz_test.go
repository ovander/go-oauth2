package auth

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzValidateRedirectURI asserts the open-redirect invariant: any accepted URI
// must use a safe scheme, carry no fragment, and resolve to the registered host
// — a fuzzer finding an accepted URI with a foreign host is an open redirect.
func FuzzValidateRedirectURI(f *testing.F) {
	for _, s := range []string{
		"https://app.example.com/cb",
		"https://evil.com/cb",
		"javascript:alert(1)",
		"data:text/html,x",
		"https://app.example.com/cb#frag",
		"https://app.example.com/../etc",
		"https://app.example.com@evil.com/cb",
		"//evil.com",
		"HTTPS://APP.EXAMPLE.COM/cb",
		"http://app.example.com/cb",
		"",
	} {
		f.Add(s)
	}
	registered := []string{"https://app.example.com/cb"}

	f.Fuzz(func(t *testing.T, uri string) {
		for _, requireHTTPS := range []bool{true, false} {
			if err := ValidateRedirectURI(uri, registered, requireHTTPS); err != nil {
				continue // rejected — fine
			}
			// Accepted: it must be safe and host-matched.
			p, perr := url.Parse(uri)
			if perr != nil {
				t.Fatalf("accepted an unparseable URI: %q", uri)
			}
			if isDangerousScheme(p.Scheme) {
				t.Fatalf("accepted a dangerous scheme: %q", uri)
			}
			if p.Fragment != "" {
				t.Fatalf("accepted a URI with a fragment: %q", uri)
			}
			if !strings.EqualFold(p.Hostname(), "app.example.com") {
				t.Fatalf("OPEN REDIRECT: accepted %q (host %q) not matching the registered host", uri, p.Hostname())
			}
		}
	})
}
