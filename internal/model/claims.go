package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// JSONMap is a free-form JSON object stored in a Postgres `jsonb` column. It is
// used for per-user attributes (A2 custom claims): arbitrary key/value data an
// operator attaches to a user (tier, employee number, cost centre, …) that a
// client can then have projected into its tokens via a claim mapping.
type JSONMap map[string]any

// Scan implements sql.Scanner (jsonb arrives as []byte, or string on some
// drivers). A NULL column yields an empty map rather than nil so callers never
// have to nil-check before reading.
func (m *JSONMap) Scan(src any) error {
	if src == nil {
		*m = JSONMap{}
		return nil
	}

	var raw []byte
	switch v := src.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into JSONMap", src)
	}

	if len(raw) == 0 {
		*m = JSONMap{}
		return nil
	}

	decoded := JSONMap{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("cannot decode JSONMap: %w", err)
	}
	*m = decoded
	return nil
}

// Value implements driver.Valuer. An empty/nil map is written as `{}` so the
// column matches its NOT NULL DEFAULT and never becomes NULL on update.
func (m JSONMap) Value() (driver.Value, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(map[string]any(m))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// Claim mapping targets: which token(s) a mapped claim is written to.
const (
	ClaimTargetAccess = "access"
	ClaimTargetID     = "id"
	ClaimTargetBoth   = "both"
)

// Claim mapping source prefixes/names. Sources are a closed set: a mapping can
// only project data the authorization server already holds, so a mapping can
// never be used to reach arbitrary state.
const (
	ClaimSourceUserAttrPrefix = "user.attributes."
	ClaimSourceLiteralPrefix  = "literal:"
	ClaimSourceUserEmail      = "user.email"
	ClaimSourceUserName       = "user.name"
	ClaimSourceUserID         = "user.id"
	ClaimSourceAppRole        = "app_role"
	ClaimSourceAppID          = "app.id"
	ClaimSourceAppClientID    = "app.client_id"
)

// ClaimMapping projects one server-held value into one token claim.
//
// In JSON a mapping is either the object form
//
//	{"source": "user.attributes.tier", "target": "both"}
//
// or the string shorthand
//
//	"user.attributes.tier"
//
// which is equivalent to the object form with target "access".
type ClaimMapping struct {
	// Source names the value to project — see the ClaimSource* constants.
	Source string `json:"source"`
	// Target is "access" (default), "id" or "both".
	Target string `json:"target,omitempty"`
}

// UnmarshalJSON accepts both the object form and the bare-string shorthand.
func (c *ClaimMapping) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		c.Source = s
		c.Target = ClaimTargetAccess
		return nil
	}

	// Object form. The alias avoids recursing back into this method.
	type alias ClaimMapping
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = ClaimMapping(a)
	if c.Target == "" {
		c.Target = ClaimTargetAccess
	}
	return nil
}

// WritesTo reports whether this mapping contributes to the given token target
// ("access" or "id").
func (c ClaimMapping) WritesTo(target string) bool {
	switch c.Target {
	case ClaimTargetBoth:
		return true
	case "":
		return target == ClaimTargetAccess
	default:
		return c.Target == target
	}
}

// ClaimMappings is a client's claim-mapping policy, keyed by the *unqualified*
// claim name. The name is namespaced at issuance time (CLAIMS_NAMESPACE) so a
// mapping can never shadow a registered or standard claim.
type ClaimMappings map[string]ClaimMapping

// Names returns the mapping keys in a stable (sorted) order. Issuance walks
// them in this order so a token's custom claims — and the size-cap decision —
// are deterministic.
func (m ClaimMappings) Names() []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Scan implements sql.Scanner for the `jsonb` column.
func (m *ClaimMappings) Scan(src any) error {
	if src == nil {
		*m = ClaimMappings{}
		return nil
	}

	var raw []byte
	switch v := src.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into ClaimMappings", src)
	}

	if len(raw) == 0 {
		*m = ClaimMappings{}
		return nil
	}

	decoded := ClaimMappings{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("cannot decode ClaimMappings: %w", err)
	}
	*m = decoded
	return nil
}

// Value implements driver.Valuer.
func (m ClaimMappings) Value() (driver.Value, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(map[string]ClaimMapping(m))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// MaxClaimName bounds a mapped claim name, so a mapping cannot bloat every
// token this client is issued.
const MaxClaimName = 64

// ValidateClaimMappings checks a mapping policy at write time (admin API), so a
// bad mapping is refused at registration rather than silently dropped at every
// token issuance. It enforces the closed source set, the three targets, and a
// syntactically usable claim name.
func ValidateClaimMappings(m ClaimMappings) error {
	for _, name := range m.Names() {
		mapping := m[name]

		if name == "" {
			return fmt.Errorf("claim mapping: empty claim name")
		}
		if len(name) > MaxClaimName {
			return fmt.Errorf("claim mapping %q: claim name exceeds %d characters", name, MaxClaimName)
		}
		if strings.ContainsAny(name, " \t\r\n\"") {
			return fmt.Errorf("claim mapping %q: claim name must not contain whitespace or quotes", name)
		}

		switch mapping.Target {
		case "", ClaimTargetAccess, ClaimTargetID, ClaimTargetBoth:
		default:
			return fmt.Errorf("claim mapping %q: unknown target %q (want access, id or both)", name, mapping.Target)
		}

		if err := validateClaimSource(name, mapping.Source); err != nil {
			return err
		}
	}
	return nil
}

func validateClaimSource(name, source string) error {
	switch {
	case source == "":
		return fmt.Errorf("claim mapping %q: source is required", name)
	case source == ClaimSourceUserEmail,
		source == ClaimSourceUserName,
		source == ClaimSourceUserID,
		source == ClaimSourceAppRole,
		source == ClaimSourceAppID,
		source == ClaimSourceAppClientID:
		return nil
	case strings.HasPrefix(source, ClaimSourceUserAttrPrefix):
		if strings.TrimPrefix(source, ClaimSourceUserAttrPrefix) == "" {
			return fmt.Errorf("claim mapping %q: source %q names no attribute", name, source)
		}
		return nil
	case strings.HasPrefix(source, ClaimSourceLiteralPrefix):
		return nil
	default:
		return fmt.Errorf("claim mapping %q: unsupported source %q", name, source)
	}
}
