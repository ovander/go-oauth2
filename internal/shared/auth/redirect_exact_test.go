package auth

import "testing"

// RedirectURIExactlyRegistered is a plain string comparison: every variant
// that ValidateRedirectURI normalizes away is not exact (#261).
func TestRedirectURIExactlyRegistered(t *testing.T) {
	registered := []string{"https://app.example.com/cb", "https://app.example.com/cb2?x=1&y=2"}
	for uri, want := range map[string]bool{
		"https://app.example.com/cb":          true,
		"https://app.example.com/cb2?x=1&y=2": true,
		"HTTPS://app.example.com/cb":          false,
		"https://APP.example.com/cb":          false,
		"https://app.example.com:443/cb":      false,
		"https://app.example.com/cb/":         false,
		"https://app.example.com/cb2?y=2&x=1": false,
		"https://app.example.com/other":       false,
	} {
		if got := RedirectURIExactlyRegistered(uri, registered); got != want {
			t.Errorf("RedirectURIExactlyRegistered(%q) = %v, want %v", uri, got, want)
		}
		// Every exact one is also accepted by the normalized check.
		if want {
			if err := ValidateRedirectURI(uri, registered, true); err != nil {
				t.Errorf("ValidateRedirectURI(%q) = %v", uri, err)
			}
		}
	}
}
