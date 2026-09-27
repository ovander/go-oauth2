package policy

import (
	"fmt"
	"net/netip"
	"regexp"
)

// Operators.
const (
	opEq         = "eq"
	opNe         = "ne"
	opIn         = "in"
	opNotIn      = "not_in"
	opContains   = "contains"
	opLt         = "lt"
	opLte        = "lte"
	opGt         = "gt"
	opGte        = "gte"
	opStartsWith = "starts_with"
	opCIDR       = "cidr"
	opExists     = "exists"
)

// Operators lists every operator, for the admin API's catalogue.
func Operators() []string {
	return []string{opEq, opNe, opIn, opNotIn, opContains, opLt, opLte, opGt, opGte, opStartsWith, opCIDR, opExists}
}

// Bounds. A rule set is evaluated on every admin request, so its size is
// bounded the way a token's custom claims are: generously for real use, firmly
// against a set that turns every decision into a scan.
const (
	MaxRules          = 200
	maxActionsPerRule = 50
	maxActionLen      = 256
	maxDescriptionLen = 500
	maxConditionDepth = 8
	maxConditionNodes = 64
	maxListValues     = 100
)

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// ValidationError locates one problem in a rule set.
type ValidationError struct {
	// Rule is the rule's ID, or "#<index>" when the ID itself is unusable.
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("rule %s: %s: %s", e.Rule, e.Path, e.Message)
}

// Validate checks a whole rule set and returns every problem found, not just
// the first, so an editor can show them all at once. A nil result means the
// set is safe to store and evaluate.
func Validate(rules []Rule) []ValidationError {
	var errs []ValidationError
	if len(rules) > MaxRules {
		errs = append(errs, ValidationError{Rule: "*", Path: "rules",
			Message: fmt.Sprintf("at most %d rules", MaxRules)})
	}

	seen := map[string]bool{}
	for i := range rules {
		r := &rules[i]
		name := r.ID
		if !ruleIDPattern.MatchString(r.ID) {
			name = fmt.Sprintf("#%d", i)
			errs = append(errs, ValidationError{Rule: name, Path: "id",
				Message: "must be 1–64 characters of a-z, 0-9, '_', '.', '-', starting with a letter or digit"})
		} else if seen[r.ID] {
			errs = append(errs, ValidationError{Rule: name, Path: "id", Message: "duplicate rule id"})
		}
		seen[r.ID] = true

		add := func(path, msg string) {
			errs = append(errs, ValidationError{Rule: name, Path: path, Message: msg})
		}

		if len(r.Description) > maxDescriptionLen {
			add("description", fmt.Sprintf("at most %d characters", maxDescriptionLen))
		}
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			add("effect", `must be "allow" or "deny"`)
		}

		switch {
		case len(r.Actions) == 0:
			add("actions", "at least one action pattern is required")
		case len(r.Actions) > maxActionsPerRule:
			add("actions", fmt.Sprintf("at most %d action patterns", maxActionsPerRule))
		}
		for j, a := range r.Actions {
			if a == "" || len(a) > maxActionLen {
				add(fmt.Sprintf("actions[%d]", j), fmt.Sprintf("must be 1–%d characters", maxActionLen))
			}
		}

		for j, o := range r.Obligations {
			if !knownObligations[o] {
				add(fmt.Sprintf("obligations[%d]", j), fmt.Sprintf("unknown obligation %q", o))
			}
		}
		if len(r.Obligations) > 0 && r.Effect == EffectDeny {
			add("obligations", "obligations are only meaningful on an allow rule")
		}

		if r.When != nil {
			v := condValidator{add: add}
			v.check(r.When, "when", 1)
			if v.nodes > maxConditionNodes {
				add("when", fmt.Sprintf("at most %d condition nodes", maxConditionNodes))
			}
		}
	}
	return errs
}

type condValidator struct {
	add   func(path, msg string)
	nodes int
}

func (v *condValidator) check(c *Condition, path string, depth int) {
	v.nodes++
	if depth > maxConditionDepth {
		v.add(path, fmt.Sprintf("nested deeper than %d levels", maxConditionDepth))
		return
	}

	shapes := 0
	if len(c.All) > 0 {
		shapes++
	}
	if len(c.Any) > 0 {
		shapes++
	}
	if c.Not != nil {
		shapes++
	}
	isLeaf := c.Attr != "" || c.Op != "" || c.Value != nil || c.Ref != ""
	if isLeaf {
		shapes++
	}
	if shapes != 1 {
		v.add(path, `must be exactly one of {"all": [...]}, {"any": [...]}, {"not": {...}} or a comparison {"attr", "op", "value"|"ref"}`)
		return
	}

	switch {
	case len(c.All) > 0:
		for i := range c.All {
			v.check(&c.All[i], fmt.Sprintf("%s.all[%d]", path, i), depth+1)
		}
	case len(c.Any) > 0:
		for i := range c.Any {
			v.check(&c.Any[i], fmt.Sprintf("%s.any[%d]", path, i), depth+1)
		}
	case c.Not != nil:
		v.check(c.Not, path+".not", depth+1)
	default:
		v.checkLeaf(c, path)
	}
}

func (v *condValidator) checkLeaf(c *Condition, path string) {
	kind, ok := lookupAttrKind(c.Attr)
	if !ok {
		v.add(path+".attr", fmt.Sprintf("unknown attribute %q", c.Attr))
		return
	}

	if c.Op == opExists {
		if c.Value != nil || c.Ref != "" {
			v.add(path, `"exists" takes neither "value" nor "ref"`)
		}
		return
	}

	switch c.Op {
	case opEq, opNe, opIn, opNotIn, opContains, opLt, opLte, opGt, opGte, opStartsWith, opCIDR:
	default:
		v.add(path+".op", fmt.Sprintf("unknown operator %q", c.Op))
		return
	}

	// Operators that only make sense for one kind of attribute.
	switch {
	case kind == kindList && c.Op != opContains:
		v.add(path+".op", fmt.Sprintf("%s is a list: use \"contains\" or \"exists\"", c.Attr))
		return
	case kind != kindList && kind != kindAny && c.Op == opContains:
		v.add(path+".op", fmt.Sprintf("%s is not a list: \"contains\" can never match", c.Attr))
		return
	case kind == kindString && (c.Op == opLt || c.Op == opLte || c.Op == opGt || c.Op == opGte):
		v.add(path+".op", fmt.Sprintf("%s is a string: ordering operators need a number", c.Attr))
		return
	case kind == kindNumber && (c.Op == opStartsWith || c.Op == opCIDR):
		v.add(path+".op", fmt.Sprintf("%s is a number", c.Attr))
		return
	case kind == kindBool && c.Op != opEq && c.Op != opNe:
		v.add(path+".op", fmt.Sprintf("%s is a boolean: use \"eq\", \"ne\" or \"exists\"", c.Attr))
		return
	}

	hasValue, hasRef := c.Value != nil, c.Ref != ""
	switch {
	case hasValue == hasRef:
		v.add(path, `exactly one of "value" or "ref" is required`)
		return
	case hasRef:
		if _, ok := lookupAttrKind(c.Ref); !ok {
			v.add(path+".ref", fmt.Sprintf("unknown attribute %q", c.Ref))
		}
		return
	}

	switch c.Op {
	case opIn, opNotIn:
		list, ok := c.Value.([]any)
		if !ok || len(list) == 0 || len(list) > maxListValues {
			v.add(path+".value", fmt.Sprintf("must be a list of 1–%d values", maxListValues))
			return
		}
		for i, item := range list {
			if !isScalar(item) {
				v.add(fmt.Sprintf("%s.value[%d]", path, i), "must be a string, number or boolean")
			}
		}
	case opCIDR:
		list, ok := c.Value.([]any)
		if !ok || len(list) == 0 || len(list) > maxListValues {
			v.add(path+".value", fmt.Sprintf("must be a list of 1–%d CIDR blocks", maxListValues))
			return
		}
		for i, item := range list {
			s, ok := item.(string)
			if _, err := netip.ParsePrefix(s); !ok || err != nil {
				v.add(fmt.Sprintf("%s.value[%d]", path, i), "must be a CIDR block such as 10.0.0.0/8")
			}
		}
	case opLt, opLte, opGt, opGte:
		if _, ok := toNumber(c.Value); !ok {
			v.add(path+".value", "must be a number")
		}
	case opStartsWith:
		if s, ok := c.Value.(string); !ok || s == "" {
			v.add(path+".value", "must be a non-empty string")
		}
	default: // eq, ne, contains
		if !isScalar(c.Value) {
			v.add(path+".value", "must be a string, number or boolean")
		}
	}
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, bool:
		return true
	}
	_, ok := toNumber(v)
	return ok
}
