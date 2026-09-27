package policy

import (
	"regexp"
	"strings"
	"time"
)

// attrKind is what an attribute holds, used to refuse conditions that could
// never be true (e.g. `principal.scopes eq "admin"` — scopes is a list) at
// save time rather than let them silently never match.
type attrKind int

const (
	kindAny    attrKind = iota // free-form attribute maps: type unknown until runtime
	kindString                 // a string
	kindNumber                 // a number
	kindList                   // a list of strings
	kindBool                   // a boolean
)

// fixedAttrs is the allow-list of attribute paths a condition may name, other
// than the three free-form attribute maps below. A path outside it is refused
// at save time: a typo in an attribute name is the single most common way to
// write a rule that silently does nothing.
var fixedAttrs = map[string]attrKind{
	"action":                  kindString,
	"principal.kind":          kindString,
	"principal.id":            kindNumber,
	"principal.role":          kindString,
	"principal.client_id":     kindString,
	"principal.app_role":      kindString,
	"principal.scopes":        kindList,
	"principal.amr":           kindList,
	"principal.auth_time_age": kindNumber,
	// must_change_password mirrors the forced-password-change gate, so that
	// gate can be expressed (and shadow-compared) as a rule like the others.
	"principal.must_change_password": kindBool,
	"app.id":                         kindNumber,
	"app.client_id":                  kindString,
	"resource.type":                  kindString,
	"resource.id":                    kindString,
	"context.ip":                     kindString,
	"context.ip_country":             kindString,
	"context.hour_utc":               kindNumber,
}

// mapAttrPrefixes are the free-form attribute maps; one further path segment
// names the key.
var mapAttrPrefixes = []string{
	"principal.attributes.",
	"resource.attributes.",
	"context.attributes.",
}

var attrKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// AttributePaths lists the fixed attribute paths plus the map prefixes, for the
// admin API's catalogue.
func AttributePaths() (fixed []string, maps []string) {
	for p := range fixedAttrs {
		fixed = append(fixed, p)
	}
	for _, p := range mapAttrPrefixes {
		maps = append(maps, p+"<key>")
	}
	return fixed, maps
}

// lookupAttrKind reports whether path is a valid attribute path and what it
// holds.
func lookupAttrKind(path string) (attrKind, bool) {
	if k, ok := fixedAttrs[path]; ok {
		return k, true
	}
	for _, prefix := range mapAttrPrefixes {
		if key, ok := strings.CutPrefix(path, prefix); ok {
			return kindAny, attrKeyPattern.MatchString(key)
		}
	}
	return kindAny, false
}

// resolve returns the value of an attribute path for an input, and whether it
// is present. Absence is meaningful: a comparison against an absent attribute
// is neither true nor false but unknown (see eval.go).
func resolve(in *Input, path string, now time.Time) (any, bool) {
	p := &in.Principal
	switch path {
	case "action":
		return in.Action, true
	case "principal.kind":
		return p.Kind, p.Kind != ""
	case "principal.id":
		return float64(p.ID), p.ID != 0
	case "principal.role":
		return p.Role, p.Role != ""
	case "principal.client_id":
		return p.ClientID, p.ClientID != ""
	case "principal.app_role":
		return p.AppRole, p.AppRole != ""
	case "principal.scopes":
		return stringsToAny(p.Scopes), p.Scopes != nil
	case "principal.amr":
		return stringsToAny(p.AMR), p.AMR != nil
	case "principal.auth_time_age":
		if p.AuthTime <= 0 {
			return nil, false
		}
		age := now.Unix() - p.AuthTime
		if age < 0 {
			age = 0 // clock skew between issuer and PDP; never negative
		}
		return float64(age), true
	case "principal.must_change_password":
		// Only meaningful for a human; absent for a client principal.
		return p.MustChangePassword, p.Kind == PrincipalUser
	case "app.id":
		if in.App == nil || in.App.ID == 0 {
			return nil, false
		}
		return float64(in.App.ID), true
	case "app.client_id":
		if in.App == nil || in.App.ClientID == "" {
			return nil, false
		}
		return in.App.ClientID, true
	case "resource.type":
		return in.Resource.Type, in.Resource.Type != ""
	case "resource.id":
		return in.Resource.ID, in.Resource.ID != ""
	case "context.ip":
		return in.Context.IP, in.Context.IP != ""
	case "context.ip_country":
		return in.Context.IPCountry, in.Context.IPCountry != ""
	case "context.hour_utc":
		return float64(now.UTC().Hour()), true
	}

	if key, ok := strings.CutPrefix(path, "principal.attributes."); ok {
		return lookupMap(p.Attributes, key)
	}
	if key, ok := strings.CutPrefix(path, "resource.attributes."); ok {
		return lookupMap(in.Resource.Attributes, key)
	}
	if key, ok := strings.CutPrefix(path, "context.attributes."); ok {
		return lookupMap(in.Context.Attributes, key)
	}
	return nil, false
}

func lookupMap(m map[string]any, key string) (any, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false
	}
	return v, true
}

func stringsToAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
