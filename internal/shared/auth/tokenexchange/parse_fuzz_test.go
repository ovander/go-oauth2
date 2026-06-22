package tokenexchange

import (
	"net/url"
	"testing"
)

// FuzzParse asserts the RFC 8693 request parser never panics on arbitrary form
// input and never returns a nil request with a nil error.
func FuzzParse(f *testing.F) {
	f.Add(GrantType, "subj", TokenTypeAccessToken, "", "", "read", "https://api")
	f.Add("not-the-grant", "", "", "", "", "", "")
	f.Add(GrantType, "subj", "weird-type", "actor", TokenTypeJWT, "", "")

	f.Fuzz(func(t *testing.T, grant, subj, subjType, actor, actorType, scope, audience string) {
		v := url.Values{}
		v.Set("grant_type", grant)
		v.Set("subject_token", subj)
		v.Set("subject_token_type", subjType)
		if actor != "" {
			v.Set("actor_token", actor)
			v.Set("actor_token_type", actorType)
		}
		v.Set("scope", scope)
		v.Set("audience", audience)

		req, err := Parse(v)
		if err == nil && req == nil {
			t.Fatal("Parse returned a nil request with a nil error")
		}
	})
}
