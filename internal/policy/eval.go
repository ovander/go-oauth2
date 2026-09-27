package policy

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// tri is three-valued logic. A comparison against an attribute that is absent,
// or of the wrong type, is neither true nor false: it is unknown.
//
// Why not just false: under false, a deny rule written as
// `principal.attributes.department ne "finance"` would silently stop denying
// every user who has no department at all — the rule fails open exactly where
// the data is incomplete. Unknown lets the combining algorithm treat the two
// effects asymmetrically: an unknown allow does not allow, an unknown deny
// denies. This is XACML's "Indeterminate" under deny-overrides, and it means a
// gap in the data can make the policy stricter, never looser.
type tri uint8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func (t tri) String() string {
	switch t {
	case triTrue:
		return "true"
	case triFalse:
		return "false"
	default:
		return "unknown"
	}
}

// Engine evaluates one immutable rule set.
type Engine struct {
	version int64
	rules   []Rule
}

// NewEngine builds an engine over rules, which must already have passed
// Validate. The slice is not copied; callers must not mutate it afterwards.
func NewEngine(version int64, rules []Rule) *Engine {
	return &Engine{version: version, rules: rules}
}

// Version is the rule-set version this engine evaluates.
func (e *Engine) Version() int64 { return e.version }

// Rules returns the engine's rule set. Callers must not mutate it.
func (e *Engine) Rules() []Rule { return e.rules }

// TraceEntry explains how one rule contributed to a decision. It is returned
// by simulation only; the decision log records the outcome, not the trace.
type TraceEntry struct {
	Rule          string   `json:"rule"`
	Effect        Effect   `json:"effect"`
	ActionMatched bool     `json:"action_matched"`
	Disabled      bool     `json:"disabled,omitempty"`
	Result        string   `json:"result,omitempty"`
	Missing       []string `json:"missing_attributes,omitempty"`
}

// Decide evaluates the input under deny-overrides:
//
//  1. any applicable deny whose condition is true or unknown → deny
//  2. otherwise any applicable allow whose condition is true → allow, carrying
//     the union of those allows' obligations
//  3. otherwise → deny (no_applicable_rule): the PDP is default-deny
func (e *Engine) Decide(in Input) Decision {
	d, _ := e.decide(in, false)
	return d
}

// Explain is Decide plus a per-rule trace, for the simulator.
func (e *Engine) Explain(in Input) (Decision, []TraceEntry) {
	return e.decide(in, true)
}

func (e *Engine) decide(in Input, trace bool) (Decision, []TraceEntry) {
	now := in.Context.Now
	if now.IsZero() {
		now = time.Now()
	}

	var (
		entries     []TraceEntry
		denyRule    string
		denyReason  string
		allowRule   string
		obligations map[string]bool
	)

	for i := range e.rules {
		r := &e.rules[i]
		entry := TraceEntry{Rule: r.ID, Effect: r.Effect, Disabled: r.Disabled}

		if r.Disabled {
			if trace {
				entries = append(entries, entry)
			}
			continue
		}
		entry.ActionMatched = matchesAnyAction(r.Actions, in.Action)
		if !entry.ActionMatched {
			if trace {
				entries = append(entries, entry)
			}
			continue
		}

		ev := evaluator{in: &in, now: now}
		result := triTrue
		if r.When != nil {
			result = ev.eval(r.When)
		}
		entry.Result = result.String()
		entry.Missing = ev.missing
		if trace {
			entries = append(entries, entry)
		}

		switch r.Effect {
		case EffectDeny:
			if result == triFalse || denyRule != "" {
				continue
			}
			denyRule = r.ID
			denyReason = ReasonDenied
			if result == triUnknown {
				denyReason = ReasonIndeterminate
			}
			// Keep going only when tracing: the outcome is already decided.
			if !trace {
				return Decision{Allow: false, Rule: denyRule, Reason: denyReason, Version: e.version}, nil
			}
		case EffectAllow:
			if result != triTrue {
				continue
			}
			if allowRule == "" {
				allowRule = r.ID
			}
			for _, o := range r.Obligations {
				if obligations == nil {
					obligations = map[string]bool{}
				}
				obligations[o] = true
			}
		}
	}

	switch {
	case denyRule != "":
		return Decision{Allow: false, Rule: denyRule, Reason: denyReason, Version: e.version}, entries
	case allowRule != "":
		return Decision{
			Allow:       true,
			Rule:        allowRule,
			Reason:      ReasonAllowed,
			Obligations: sortedKeys(obligations),
			Version:     e.version,
		}, entries
	default:
		return Decision{Allow: false, Reason: ReasonNoApplicable, Version: e.version}, entries
	}
}

// evaluator walks one rule's condition tree, remembering which attributes it
// found absent so the simulator can say why a rule came out unknown.
type evaluator struct {
	in      *Input
	now     time.Time
	missing []string
}

func (ev *evaluator) eval(c *Condition) tri {
	switch {
	case len(c.All) > 0:
		out := triTrue
		for i := range c.All {
			switch ev.eval(&c.All[i]) {
			case triFalse:
				return triFalse
			case triUnknown:
				out = triUnknown
			}
		}
		return out
	case len(c.Any) > 0:
		out := triFalse
		for i := range c.Any {
			switch ev.eval(&c.Any[i]) {
			case triTrue:
				return triTrue
			case triUnknown:
				out = triUnknown
			}
		}
		return out
	case c.Not != nil:
		switch ev.eval(c.Not) {
		case triTrue:
			return triFalse
		case triFalse:
			return triTrue
		default:
			return triUnknown
		}
	default:
		return ev.compare(c)
	}
}

func (ev *evaluator) attr(path string) (any, bool) {
	v, ok := resolve(ev.in, path, ev.now)
	if !ok {
		ev.missing = append(ev.missing, path)
	}
	return v, ok
}

func (ev *evaluator) compare(c *Condition) tri {
	if c.Op == opExists {
		_, ok := resolve(ev.in, c.Attr, ev.now)
		return boolTri(ok)
	}

	left, ok := ev.attr(c.Attr)
	if !ok {
		return triUnknown
	}
	right := c.Value
	if c.Ref != "" {
		if right, ok = ev.attr(c.Ref); !ok {
			return triUnknown
		}
	}

	switch c.Op {
	case opEq:
		return boolTri(equal(left, right))
	case opNe:
		return boolTri(!equal(left, right))
	case opIn, opNotIn:
		list, ok := right.([]any)
		if !ok {
			return triUnknown
		}
		found := false
		for _, item := range list {
			if equal(left, item) {
				found = true
				break
			}
		}
		if c.Op == opNotIn {
			found = !found
		}
		return boolTri(found)
	case opContains:
		list, ok := left.([]any)
		if !ok {
			return triUnknown
		}
		for _, item := range list {
			if equal(item, right) {
				return triTrue
			}
		}
		return triFalse
	case opLt, opLte, opGt, opGte:
		a, aok := toNumber(left)
		b, bok := toNumber(right)
		if !aok || !bok {
			return triUnknown
		}
		switch c.Op {
		case opLt:
			return boolTri(a < b)
		case opLte:
			return boolTri(a <= b)
		case opGt:
			return boolTri(a > b)
		default:
			return boolTri(a >= b)
		}
	case opStartsWith:
		a, aok := left.(string)
		b, bok := right.(string)
		if !aok || !bok {
			return triUnknown
		}
		return boolTri(strings.HasPrefix(a, b))
	case opCIDR:
		s, ok := left.(string)
		if !ok {
			return triUnknown
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return triUnknown
		}
		addr = addr.Unmap()
		list, ok := right.([]any)
		if !ok {
			return triUnknown
		}
		for _, item := range list {
			ps, ok := item.(string)
			if !ok {
				continue
			}
			if prefix, err := netip.ParsePrefix(ps); err == nil && prefix.Contains(addr) {
				return triTrue
			}
		}
		return triFalse
	}
	return triUnknown
}

func boolTri(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

// equal compares two scalars. Numbers compare numerically whatever their Go
// type (attributes decoded from JSON are float64, IDs are uint); strings and
// booleans compare exactly; anything else, including a type mismatch, is
// simply not equal.
func equal(a, b any) bool {
	if an, ok := toNumber(a); ok {
		bn, ok := toNumber(b)
		return ok && an == bn
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	}
	return false
}

func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint64:
		return float64(n), true
	case uint32:
		return float64(n), true
	}
	return 0, false
}

// matchesAnyAction reports whether any glob pattern matches the action.
func matchesAnyAction(patterns []string, action string) bool {
	for _, p := range patterns {
		if globMatch(p, action) {
			return true
		}
	}
	return false
}

// globMatch matches s against a pattern in which `*` stands for any run of
// characters (including `/` and spaces) and every other character is literal.
// Iterative with single backtracking, so it is linear-ish and cannot be made
// exponential by a hostile pattern.
func globMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && pattern[p] == s[i]:
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
