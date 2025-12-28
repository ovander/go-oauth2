package auth

import (
	"errors"
	"net/url"
	"strings"
)

// Redirect URI validation errors
var (
	ErrRedirectURIEmpty           = errors.New("redirect URI cannot be empty")
	ErrRedirectURIInvalidURL      = errors.New("redirect URI is not a valid URL")
	ErrRedirectURIHasFragment     = errors.New("redirect URI must not contain a fragment")
	ErrRedirectURINotHTTPS        = errors.New("redirect URI must use HTTPS in production")
	ErrRedirectURINotRegistered   = errors.New("redirect URI is not registered for this client")
	ErrRedirectURIPathTraversal   = errors.New("redirect URI contains path traversal")
	ErrRedirectURIDangerousScheme = errors.New("redirect URI uses a dangerous scheme")
)

// ValidateRedirectURI validates a redirect URI according to OAuth 2.0 security best practices
// See: RFC 6749 Section 3.1.2 and OAuth 2.0 Security BCP
func ValidateRedirectURI(uri string, registeredURIs []string, requireHTTPS bool) error {
	if uri == "" {
		return ErrRedirectURIEmpty
	}

	// Parse the URI
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return ErrRedirectURIInvalidURL
	}

	// Check for dangerous schemes (XSS prevention)
	if isDangerousScheme(parsedURI.Scheme) {
		return ErrRedirectURIDangerousScheme
	}

	// Check for fragment (not allowed per RFC 6749)
	if parsedURI.Fragment != "" {
		return ErrRedirectURIHasFragment
	}

	// Check for HTTPS requirement (except for localhost in development)
	if requireHTTPS && !isLocalhostURI(parsedURI) && parsedURI.Scheme != "https" {
		return ErrRedirectURINotHTTPS
	}

	// Check for path traversal attempts
	if containsPathTraversal(parsedURI.Path) {
		return ErrRedirectURIPathTraversal
	}

	// Normalize and compare against registered URIs
	normalizedURI := normalizeRedirectURI(parsedURI)
	for _, registeredURI := range registeredURIs {
		registeredParsed, err := url.Parse(registeredURI)
		if err != nil {
			continue
		}
		normalizedRegistered := normalizeRedirectURI(registeredParsed)
		if normalizedURI == normalizedRegistered {
			return nil
		}
	}

	return ErrRedirectURINotRegistered
}

// ValidateRedirectURILoose performs a less strict validation for development environments
func ValidateRedirectURILoose(uri string, registeredURIs []string) error {
	return ValidateRedirectURI(uri, registeredURIs, false)
}

// ValidateRedirectURIStrict performs strict validation for production environments
func ValidateRedirectURIStrict(uri string, registeredURIs []string) error {
	return ValidateRedirectURI(uri, registeredURIs, true)
}

// isLocalhostURI checks if the URI is for localhost (development)
func isLocalhostURI(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

// isDangerousScheme checks if the URI scheme could be used for XSS or other attacks
func isDangerousScheme(scheme string) bool {
	dangerousSchemes := []string{
		"javascript",
		"data",
		"vbscript",
		"file",
	}
	lowerScheme := strings.ToLower(scheme)
	for _, dangerous := range dangerousSchemes {
		if lowerScheme == dangerous {
			return true
		}
	}
	return false
}

// containsPathTraversal checks for path traversal sequences
func containsPathTraversal(path string) bool {
	// Normalize the path first
	normalized := strings.ReplaceAll(path, "\\", "/")

	// Check for common path traversal patterns
	patterns := []string{
		"../",
		"..\\",
		"..",
		"/./",
		"/..",
		"..%2f",
		"..%5c",
		"%2e%2e",
		"%252e%252e",
	}

	lowerPath := strings.ToLower(normalized)
	for _, pattern := range patterns {
		if strings.Contains(lowerPath, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// normalizeRedirectURI normalizes a redirect URI for comparison
func normalizeRedirectURI(u *url.URL) string {
	// Create a copy to avoid modifying the original
	normalized := *u

	// Lowercase the scheme and host
	normalized.Scheme = strings.ToLower(normalized.Scheme)
	normalized.Host = strings.ToLower(normalized.Host)

	// Remove default ports
	if (normalized.Scheme == "http" && normalized.Port() == "80") ||
		(normalized.Scheme == "https" && normalized.Port() == "443") {
		normalized.Host = normalized.Hostname()
	}

	// Normalize the path (remove trailing slashes for consistency)
	normalized.Path = strings.TrimSuffix(normalized.Path, "/")
	if normalized.Path == "" {
		normalized.Path = "/"
	}

	// Remove fragment (should already be empty)
	normalized.Fragment = ""

	// Sort query parameters for consistent comparison
	normalized.RawQuery = normalized.Query().Encode()

	return normalized.String()
}

// IsValidRedirectURIFormat checks if a URI is a valid format for registration
func IsValidRedirectURIFormat(uri string) error {
	if uri == "" {
		return ErrRedirectURIEmpty
	}

	parsedURI, err := url.Parse(uri)
	if err != nil {
		return ErrRedirectURIInvalidURL
	}

	// Must have a scheme
	if parsedURI.Scheme == "" {
		return errors.New("redirect URI must have a scheme (http or https)")
	}

	// Check for dangerous schemes (XSS prevention)
	if isDangerousScheme(parsedURI.Scheme) {
		return ErrRedirectURIDangerousScheme
	}

	// Must have a host
	if parsedURI.Host == "" {
		return errors.New("redirect URI must have a host")
	}

	// No fragment allowed
	if parsedURI.Fragment != "" {
		return ErrRedirectURIHasFragment
	}

	// Check for path traversal
	if containsPathTraversal(parsedURI.Path) {
		return ErrRedirectURIPathTraversal
	}

	return nil
}
