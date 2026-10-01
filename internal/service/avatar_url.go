package service

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// MaxAvatarURLLength bounds a stored avatar URL.
const MaxAvatarURLLength = 2048

// ErrInvalidAvatarURL is returned when an avatar URL is not acceptable.
var ErrInvalidAvatarURL = errors.New("invalid avatar_url")

// normalizeAvatarURL trims raw and validates it as an avatar URL: an absolute
// https URL with a host, no credentials and at most MaxAvatarURLLength
// characters. Socrate only stores the URL; it is rendered as an image by
// applications, so anything but https (javascript:, data:, http:) is refused.
// An empty value means "no avatar" and yields nil.
func normalizeAvatarURL(raw string) (*string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > MaxAvatarURLLength {
		return nil, fmt.Errorf("%w: longer than %d characters", ErrInvalidAvatarURL, MaxAvatarURLLength)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return nil, fmt.Errorf("%w: must not contain whitespace", ErrInvalidAvatarURL)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: not an absolute URL", ErrInvalidAvatarURL)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("%w: must use https", ErrInvalidAvatarURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: must not contain credentials", ErrInvalidAvatarURL)
	}
	return &raw, nil
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
