package policy

import (
	"slices"
	"time"
)

// UnmetObligation returns the first of obligations that an authentication
// does not satisfy, or "". amr and authTime come from the user's access token
// (nil and 0 when there is none). freshMaxAge is the require_fresh_auth window;
// zero or less disables that check. An obligation this version does not know
// is unmet: it cannot be honoured, so it is never silently dropped.
//
// It is the check both enforcement points inside Socrate apply: the admin API's
// PEP, and the decide endpoint when it logs what an application's PEP will do.
func UnmetObligation(obligations []string, amr []string, authTime int64, freshMaxAge time.Duration, now time.Time) string {
	for _, o := range obligations {
		switch o {
		case ObligationFreshAuth:
			if freshMaxAge <= 0 {
				continue
			}
			if authTime == 0 || now.Sub(time.Unix(authTime, 0)) > freshMaxAge {
				return o
			}
		case ObligationMFA:
			if !slices.Contains(amr, "mfa") {
				return o
			}
		default:
			return o
		}
	}
	return ""
}
