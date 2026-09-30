package service

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

var (
	// ErrInvalidMagicLinkURL is returned when an app's magic_link_url is not an
	// acceptable landing page (see validateMagicLinkURL).
	ErrInvalidMagicLinkURL = errors.New("invalid magic_link_url")

	// ErrMagicLinkNotConfigured is returned when an app without a
	// magic_link_url asks for a magic link: the email would have no page to
	// open, so none is sent.
	ErrMagicLinkNotConfigured = errors.New("magic links are not configured for this app: set its magic_link_url")
)

// validateMagicLinkURL checks the page a magic-link email opens. That page
// receives a single-use login token, so it gets the same trust as a redirect
// URI: an absolute https URL (http only for localhost), no credentials, no
// fragment, no path traversal, no token or client_id parameter of its own, and
// the same origin as one of the app's registered redirect URIs.
func validateMagicLinkURL(raw string, redirectURIs []string) error {
	if err := auth.IsValidRedirectURIFormat(raw); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidMagicLinkURL, err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: not a valid URL", ErrInvalidMagicLinkURL)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("%w: must use https (http is accepted for localhost only)", ErrInvalidMagicLinkURL)
		}
	default:
		return fmt.Errorf("%w: must use https", ErrInvalidMagicLinkURL)
	}
	if u.User != nil {
		return fmt.Errorf("%w: must not contain credentials", ErrInvalidMagicLinkURL)
	}
	q := u.Query()
	if q.Has("token") || q.Has("client_id") {
		return fmt.Errorf("%w: must not set the token or client_id parameter (Socrate adds them)", ErrInvalidMagicLinkURL)
	}
	origin := urlOrigin(u)
	for _, r := range redirectURIs {
		ru, err := url.Parse(r)
		if err == nil && ru.Host != "" && urlOrigin(ru) == origin {
			return nil
		}
	}
	return fmt.Errorf("%w: must have the same origin as one of the app's redirect_uris", ErrInvalidMagicLinkURL)
}

// normalizeMagicLinkURL trims raw and validates it against redirectURIs. An
// empty value means "not configured" and yields nil.
func normalizeMagicLinkURL(raw string, redirectURIs []string) (*string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if err := validateMagicLinkURL(raw, redirectURIs); err != nil {
		return nil, err
	}
	return &raw, nil
}

// magicLinkEmailURL builds the link a magic-link email carries: the app's
// landing page with token and client_id added to its query.
func magicLinkEmailURL(app *model.App, rawToken string) (string, error) {
	if app.MagicLinkURL == nil || strings.TrimSpace(*app.MagicLinkURL) == "" {
		return "", ErrMagicLinkNotConfigured
	}
	u, err := url.Parse(strings.TrimSpace(*app.MagicLinkURL))
	if err != nil || u.Host == "" {
		return "", ErrMagicLinkNotConfigured
	}
	q := u.Query()
	q.Set("token", rawToken)
	q.Set("client_id", app.ClientID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// urlOrigin returns scheme://host[:port] in lower case, without a default port.
func urlOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		return scheme + "://" + host + ":" + port
	}
	return scheme + "://" + host
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
