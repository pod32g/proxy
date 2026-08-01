// Package policy decides where the proxy is willing to connect on a client's
// behalf.
//
// Rules are an ordered, first-match-wins list. The ordering is the whole point
// of the design and constrains how evaluation works: a domain rule is decidable
// from the request, but a CIDR rule needs the address DNS resolved to, and the
// two are known at different moments. Evaluating each kind in its own pass would
// silently reorder them — given
//
//	allow cidr 10.0.0.0/8
//	deny  all
//
// a hostname-only pass that skipped the CIDR rule would reach "deny all" and
// reject a name that resolves into 10/8, which is the opposite of what the list
// says. So the authoritative evaluation happens once, after DNS, with both the
// hostname and the resolved address in hand.
package policy

import (
	"fmt"
	"net"
	"strings"
)

// Decision is the outcome of evaluating a rule set.
type Decision int

const (
	// Undecided means no rule matched, or none could be evaluated yet.
	Undecided Decision = iota
	Allow
	Deny
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return "undecided"
	}
}

// Kind is what a rule matches on.
type Kind string

const (
	// KindDomain matches the requested hostname.
	KindDomain Kind = "domain"
	// KindCIDR matches the address the hostname resolved to.
	KindCIDR Kind = "cidr"
	// KindAll matches everything, for a terminal default.
	KindAll Kind = "all"
)

// Rule is one entry in an ordered list.
type Rule struct {
	Action Decision
	Kind   Kind
	// Value as written, kept for round-tripping and for error messages.
	Value string

	net *net.IPNet
}

// String renders the rule in the syntax Parse accepts.
func (r Rule) String() string {
	if r.Kind == KindAll {
		return fmt.Sprintf("%s all", r.Action)
	}
	return fmt.Sprintf("%s %s %s", r.Action, r.Kind, r.Value)
}

// ParseRule reads one rule: "allow domain *.example.com", "deny cidr
// 10.0.0.0/8", "deny all".
func ParseRule(line string) (Rule, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return Rule{}, fmt.Errorf("rule %q: want \"<allow|deny> <domain|cidr> <value>\" or \"<allow|deny> all\"", line)
	}

	var action Decision
	switch strings.ToLower(fields[0]) {
	case "allow":
		action = Allow
	case "deny":
		action = Deny
	default:
		return Rule{}, fmt.Errorf("rule %q: first word must be allow or deny", line)
	}

	kind := Kind(strings.ToLower(fields[1]))
	switch kind {
	case KindAll:
		if len(fields) != 2 {
			return Rule{}, fmt.Errorf("rule %q: \"all\" takes no value", line)
		}
		return Rule{Action: action, Kind: KindAll}, nil
	case KindDomain, KindCIDR:
		if len(fields) != 3 {
			return Rule{}, fmt.Errorf("rule %q: %s needs exactly one value", line, kind)
		}
	default:
		return Rule{}, fmt.Errorf("rule %q: unknown matcher %q (want domain, cidr or all)", line, fields[1])
	}

	value := fields[2]
	rule := Rule{Action: action, Kind: kind, Value: value}
	if kind == KindCIDR {
		// A bare address is accepted as a single-host rule; requiring /32 is a
		// papercut with no upside.
		if !strings.Contains(value, "/") {
			if ip := net.ParseIP(value); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				value = fmt.Sprintf("%s/%d", value, bits)
			}
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return Rule{}, fmt.Errorf("rule %q: %v", line, err)
		}
		rule.net = network
	}
	if kind == KindDomain && value == "" {
		return Rule{}, fmt.Errorf("rule %q: empty domain", line)
	}
	return rule, nil
}

// RuleSet is an ordered list of rules plus the decision to fall back on.
type RuleSet struct {
	Rules []Rule
	// Default applies when no rule matches. Undecided means "no opinion", which
	// leaves the built-in private-address protection as the only constraint.
	Default Decision
}

// Parse reads a rule per line. Blank lines and # comments are ignored so a rule
// set can be commented in a config file or the UI.
func Parse(text string) (*RuleSet, error) {
	set := &RuleSet{}
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rule, err := ParseRule(trimmed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		set.Rules = append(set.Rules, rule)
	}
	return set, nil
}

// String renders the set back to the syntax Parse accepts.
func (s *RuleSet) String() string {
	if s == nil {
		return ""
	}
	lines := make([]string, 0, len(s.Rules))
	for _, r := range s.Rules {
		lines = append(lines, r.String())
	}
	return strings.Join(lines, "\n")
}

// Empty reports whether the set constrains anything.
func (s *RuleSet) Empty() bool { return s == nil || len(s.Rules) == 0 }

// matchDomain reports whether host matches a domain pattern.
//
//	example.com    exact, and also matches subdomains
//	*.example.com  subdomains only, not the apex
//	*              everything
//
// Bare "example.com" covering subdomains is the behaviour people expect from
// this kind of list; "*.example.com" is available when the apex must be
// excluded deliberately.
func matchDomain(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if pattern == "*" {
		return true
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

// Match reports the decision for a destination, and the rule responsible.
//
// ip may be nil, meaning DNS has not run yet. In that case evaluation stops at
// the first CIDR rule and returns Undecided: continuing past a rule that cannot
// be evaluated would let a later rule decide out of order.
func (s *RuleSet) Match(host string, ip net.IP) (Decision, *Rule) {
	if s == nil {
		return Undecided, nil
	}
	for i := range s.Rules {
		rule := &s.Rules[i]
		switch rule.Kind {
		case KindAll:
			return rule.Action, rule
		case KindDomain:
			if matchDomain(rule.Value, host) {
				return rule.Action, rule
			}
		case KindCIDR:
			if ip == nil {
				return Undecided, nil
			}
			if rule.net != nil && rule.net.Contains(ip) {
				return rule.Action, rule
			}
		}
	}
	if s.Default != Undecided {
		return s.Default, nil
	}
	return Undecided, nil
}
