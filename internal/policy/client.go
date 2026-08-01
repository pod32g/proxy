package policy

import (
	"fmt"
	"net"
	"strings"
)

// ClientRule says whether an address may use the proxy, and optionally
// constrains where it may go.
type ClientRule struct {
	Action Decision
	// Value as written, for round-tripping and error messages.
	Value string
	// Rules, when present, replace the global destination rules for this
	// client. Nil means the global set applies unchanged.
	Rules *RuleSet

	net *net.IPNet
}

// String renders the rule in the syntax ParseClientRule accepts.
func (r ClientRule) String() string {
	line := fmt.Sprintf("%s %s", r.Action, r.Value)
	if r.Rules != nil && !r.Rules.Empty() {
		parts := make([]string, 0, len(r.Rules.Rules))
		for _, d := range r.Rules.Rules {
			parts = append(parts, d.String())
		}
		line += " { " + strings.Join(parts, "; ") + " }"
	}
	return line
}

// ones returns the prefix length, used to rank specificity.
func (r ClientRule) ones() int {
	if r.net == nil {
		return -1
	}
	n, _ := r.net.Mask.Size()
	return n
}

// ParseClientRule reads one entry:
//
//	allow 10.0.0.0/8
//	deny  10.1.2.3
//	allow 192.168.0.0/16 { allow domain example.com; deny all }
//
// The braced part, when present, is a destination rule set for that client and
// uses exactly the syntax of the global rules — one matcher, not two.
func ParseClientRule(line string) (ClientRule, error) {
	line = strings.TrimSpace(line)

	var nested string
	if open := strings.Index(line, "{"); open >= 0 {
		closing := strings.LastIndex(line, "}")
		if closing < open {
			return ClientRule{}, fmt.Errorf("client rule %q: unclosed {", line)
		}
		nested = line[open+1 : closing]
		line = strings.TrimSpace(line[:open])
	}

	fields := strings.Fields(line)
	if len(fields) != 2 {
		return ClientRule{}, fmt.Errorf("client rule %q: want \"<allow|deny> <address-or-cidr>\"", line)
	}

	var action Decision
	switch strings.ToLower(fields[0]) {
	case "allow":
		action = Allow
	case "deny":
		action = Deny
	default:
		return ClientRule{}, fmt.Errorf("client rule %q: first word must be allow or deny", line)
	}

	value := fields[1]
	cidr := value
	// A bare address is a single-host entry; making people write /32 is a
	// papercut with no upside.
	if !strings.Contains(cidr, "/") {
		if ip := net.ParseIP(cidr); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			cidr = fmt.Sprintf("%s/%d", cidr, bits)
		}
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return ClientRule{}, fmt.Errorf("client rule %q: %v", line, err)
	}

	rule := ClientRule{Action: action, Value: value, net: network}
	if strings.TrimSpace(nested) != "" {
		set, err := Parse(strings.ReplaceAll(nested, ";", "\n"))
		if err != nil {
			return ClientRule{}, fmt.Errorf("client rule %q: %w", line, err)
		}
		rule.Rules = set
	}
	return rule, nil
}

// ClientSet is a table of client entries plus the default for addresses that
// appear in none of them.
type ClientSet struct {
	Rules []ClientRule
	// Default governs unlisted clients. Allow makes the table a denylist,
	// Deny makes it an allowlist; Undecided means the table has no opinion and
	// every client may connect.
	Default Decision
}

// ParseClients reads a client rule per line, ignoring blanks and # comments.
func ParseClients(text string) (*ClientSet, error) {
	set := &ClientSet{}
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// A bare "default allow" / "default deny" line sets the fallback, so a
		// table can be read top to bottom without a separate setting.
		if fields := strings.Fields(trimmed); len(fields) == 2 && strings.EqualFold(fields[0], "default") {
			switch strings.ToLower(fields[1]) {
			case "allow":
				set.Default = Allow
			case "deny":
				set.Default = Deny
			default:
				return nil, fmt.Errorf("line %d: default must be allow or deny", i+1)
			}
			continue
		}
		rule, err := ParseClientRule(trimmed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		set.Rules = append(set.Rules, rule)
	}
	return set, nil
}

// String renders the set back to the syntax ParseClients accepts.
func (s *ClientSet) String() string {
	if s == nil {
		return ""
	}
	lines := make([]string, 0, len(s.Rules)+1)
	for _, r := range s.Rules {
		lines = append(lines, r.String())
	}
	if s.Default != Undecided {
		lines = append(lines, "default "+s.Default.String())
	}
	return strings.Join(lines, "\n")
}

// Empty reports whether the set constrains anything.
func (s *ClientSet) Empty() bool {
	return s == nil || (len(s.Rules) == 0 && s.Default == Undecided)
}

// Match reports whether an address may use the proxy, and returns the entry
// responsible.
//
// The most specific matching prefix wins, rather than the first match. A client
// table is a description of a network, not a policy written in priority order:
// given "allow 10.0.0.0/8" and "deny 10.1.2.3", the host must be denied
// whichever order they happen to appear in. Writing the more specific entry
// first would otherwise be load-bearing and easy to get wrong.
func (s *ClientSet) Match(clientIP string) (Decision, *ClientRule) {
	if s == nil {
		return Undecided, nil
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		// An unparseable address cannot be matched against any prefix. Fall
		// through to the default rather than guessing.
		if s.Default != Undecided {
			return s.Default, nil
		}
		return Undecided, nil
	}

	var best *ClientRule
	for i := range s.Rules {
		rule := &s.Rules[i]
		if rule.net == nil || !rule.net.Contains(ip) {
			continue
		}
		if best == nil || rule.ones() > best.ones() {
			best = rule
		}
	}
	if best != nil {
		return best.Action, best
	}
	if s.Default != Undecided {
		return s.Default, nil
	}
	return Undecided, nil
}

// DestinationsFor returns the destination rules that apply to a client: the
// client's own set when it has one, otherwise the global set.
func (s *ClientSet) DestinationsFor(clientIP string, global *RuleSet) *RuleSet {
	if _, rule := s.Match(clientIP); rule != nil && rule.Rules != nil {
		return rule.Rules
	}
	return global
}
