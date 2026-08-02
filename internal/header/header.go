// Package header applies conditional header rules to proxied requests and
// responses.
//
// A rule is an action, a header, and an optional destination condition reusing
// the matcher from the destination policy — so there is one matching syntax to
// learn rather than two that drift apart.
//
// Order of application is a contract, not an accident, and is documented on
// RuleSet.Apply.
package header

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/pod32g/proxy/internal/policy"
)

// Action is what a rule does to a header.
type Action string

const (
	// Set replaces every existing value with this one, adding it if absent.
	Set Action = "set"
	// Add appends a value, keeping any already present. For headers that are
	// genuinely lists, which Set would flatten.
	Add Action = "add"
	// Remove deletes the header.
	Remove Action = "remove"
	// Replace sets the header only when it is already present, so a rule can
	// rewrite what a client sent without inventing one it did not.
	Replace Action = "replace"
)

// Direction says whether a rule applies to the request going upstream or the
// response coming back.
type Direction string

const (
	Request  Direction = "request"
	Response Direction = "response"
)

// Rule is one header instruction.
type Rule struct {
	Direction Direction
	Action    Action
	Name      string
	Value     string

	// Condition, when non-nil, limits the rule to matching destinations.
	Condition *policy.Rule

	// text is the rule as written, for round-tripping to the store and the UI.
	text string
}

// String renders the rule in the syntax Parse accepts.
func (r Rule) String() string {
	if r.text != "" {
		return r.text
	}
	var b strings.Builder
	if r.Direction == Response {
		b.WriteString("response ")
	}
	b.WriteString(string(r.Action))
	b.WriteByte(' ')
	b.WriteString(r.Name)
	if r.Action != Remove {
		b.WriteString(": ")
		b.WriteString(r.Value)
	}
	if r.Condition != nil {
		b.WriteString(" for ")
		b.WriteString(strings.TrimPrefix(r.Condition.String(), "allow "))
	}
	return b.String()
}

// forbidden are headers no rule may touch, in either direction.
//
// PROXY-6 strips the hop-by-hop set because forwarding it breaks RFC 7230 §6.1
// and, in the case of Proxy-Authorization, hands every origin the credentials a
// client used on the proxy. A rule that could re-add one would bring both
// straight back.
//
// Connection is in the list for a reason that is easy to miss: it is how a
// sender *extends* the hop-by-hop set, so "set Connection: X-Secret" makes an
// arbitrary header per-hop. Blocking only the named headers would leave that
// lever untouched.
var forbidden = map[string]string{
	"connection":          "Connection controls which headers are hop-by-hop; a rule here could make any header per-hop",
	"keep-alive":          "hop-by-hop (RFC 7230 §6.1)",
	"proxy-authenticate":  "hop-by-hop; re-adding it would forward the proxy's own challenge",
	"proxy-authorization": "hop-by-hop; forwarding it hands origins the credentials clients use on this proxy",
	"proxy-connection":    "hop-by-hop",
	"te":                  "hop-by-hop (RFC 7230 §6.1)",
	"trailer":             "hop-by-hop (RFC 7230 §6.1)",
	"transfer-encoding":   "hop-by-hop; the transport owns this and rewriting it corrupts framing",
	"upgrade":             "hop-by-hop; the upgrade path re-issues this deliberately",
	"content-length":      "the transport owns this; rewriting it corrupts framing",
}

// Forbidden reports whether a rule may set a header, and why not.
//
// Exported so the relationship between this list and the hop-by-hop set the
// proxy strips can be asserted rather than trusted. The two are separate lists
// by necessity — this one also covers Content-Length, which is not hop-by-hop —
// but every header the proxy strips must appear here, or a rule could put back
// what the strip exists to remove. Nothing enforced that; a test does now.
func Forbidden(name string) (why string, blocked bool) {
	why, blocked = forbidden[strings.ToLower(name)]
	return why, blocked
}

// ParseRule reads one rule.
//
//	set X-Internal: 1
//	set X-Internal: 1 for domain internal.example.com
//	add X-Trace: on for domain *.example.com
//	remove X-Debug
//	replace User-Agent: proxy
//	response set X-Via: proxy
func ParseRule(line string) (Rule, error) {
	original := strings.TrimSpace(line)
	rest := original

	rule := Rule{Direction: Request, text: original}
	for _, prefix := range []struct {
		word string
		dir  Direction
	}{{"response ", Response}, {"request ", Request}} {
		if trimmed, ok := cutPrefixFold(rest, prefix.word); ok {
			rule.Direction = prefix.dir
			rest = trimmed
			break
		}
	}

	// The condition is split off first: a header value may contain anything,
	// including the word "for", so it has to be taken from the end.
	if idx := lastIndexFold(rest, " for "); idx >= 0 {
		condText := strings.TrimSpace(rest[idx+len(" for "):])
		// Parsed as an allow rule purely to reuse the matcher; the action is
		// carried by the header rule, not by this.
		parsed, err := policy.ParseRule("allow " + condText)
		if err != nil {
			return Rule{}, fmt.Errorf("rule %q: condition: %v", original, err)
		}
		// A cidr condition cannot be honoured here and is rejected rather than
		// accepted and quietly never matched.
		//
		// Headers have to be set before the request is made, and the
		// destination's address is not known until the dial — which happens
		// after. The destination policy can use cidr rules because it runs
		// inside ControlContext, with the resolved address in hand; there is no
		// equivalent moment for a header. Accepting one would be the same
		// failure this package rejects hop-by-hop rules to avoid: a rule that
		// looks configured and does nothing.
		if parsed.Kind == policy.KindCIDR {
			return Rule{}, fmt.Errorf(
				"rule %q: cidr conditions are not supported on header rules — headers are set "+
					"before the destination is resolved, so the address is not known yet; "+
					"use a domain condition", original)
		}
		rule.Condition = &parsed
		rest = strings.TrimSpace(rest[:idx])
	}

	verb, remainder, found := strings.Cut(rest, " ")
	if !found {
		return Rule{}, fmt.Errorf("rule %q: want \"<set|add|remove|replace> <Header>[: value]\"", original)
	}
	switch Action(strings.ToLower(verb)) {
	case Set:
		rule.Action = Set
	case Add:
		rule.Action = Add
	case Remove:
		rule.Action = Remove
	case Replace:
		rule.Action = Replace
	default:
		return Rule{}, fmt.Errorf("rule %q: unknown action %q (want set, add, remove or replace)", original, verb)
	}

	name, value, hasValue := strings.Cut(strings.TrimSpace(remainder), ":")
	rule.Name = http.CanonicalHeaderKey(strings.TrimSpace(name))
	rule.Value = strings.TrimSpace(value)

	if rule.Name == "" {
		return Rule{}, fmt.Errorf("rule %q: no header named", original)
	}
	if rule.Action == Remove && hasValue && rule.Value != "" {
		return Rule{}, fmt.Errorf("rule %q: remove takes no value", original)
	}
	if rule.Action != Remove && !hasValue {
		return Rule{}, fmt.Errorf("rule %q: %s needs \"Header: value\"", original, rule.Action)
	}
	if err := validHeaderName(rule.Name); err != nil {
		return Rule{}, fmt.Errorf("rule %q: %v", original, err)
	}
	if err := validHeaderValue(rule.Value); err != nil {
		return Rule{}, fmt.Errorf("rule %q: %v", original, err)
	}

	// Rejected here rather than filtered at apply time. A rule that can never
	// take effect should fail where it is written, naming the header — not
	// silently do nothing and leave somebody debugging why their configuration
	// has no effect.
	if why, blocked := Forbidden(rule.Name); blocked {
		return Rule{}, fmt.Errorf("rule %q: %s may not be set by a rule: %s", original, rule.Name, why)
	}
	return rule, nil
}

// validHeaderName rejects anything that is not a token, so a rule cannot inject
// a second header by embedding a separator.
func validHeaderName(name string) error {
	if name == "" {
		return fmt.Errorf("empty header name")
	}
	for _, r := range name {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(":()<>@,;\\\"/[]?={}", r) {
			return fmt.Errorf("header name %q contains an invalid character", name)
		}
	}
	return nil
}

// validHeaderValue rejects control characters. A newline in a value is response
// splitting: it ends the header and starts whatever the author wants next.
func validHeaderValue(value string) error {
	for _, r := range value {
		if r == '\n' || r == '\r' || r == 0 {
			return fmt.Errorf("header value contains a control character")
		}
	}
	return nil
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

func lastIndexFold(s, sep string) int {
	lower := strings.ToLower(s)
	return strings.LastIndex(lower, strings.ToLower(sep))
}

// RuleSet is an ordered list of header rules.
type RuleSet struct {
	Rules []Rule
}

// Parse reads a rule per line, ignoring blanks and # comments.
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

// Empty reports whether the set does anything.
func (s *RuleSet) Empty() bool { return s == nil || len(s.Rules) == 0 }

// Apply runs the rules for one direction against a header set.
//
// Order is a contract, documented in the README, not an emergent property:
//
//  1. Hop-by-hop stripping happens before any of this and is not something a
//     rule can precede or undo.
//  2. Rules run in the order written. Later wins, which is what makes a general
//     rule followed by a specific exception behave the way it reads.
//  3. The proxy identity headers are applied after all rules, so a rule cannot
//     make the proxy misreport what it is.
//
// host and ip describe the destination, for conditions. ip may be nil when it
// is not known, in which case cidr conditions do not match — the same
// conservative reading the destination policy takes.
func (s *RuleSet) Apply(h http.Header, dir Direction, host string, ip net.IP) {
	if s == nil || h == nil {
		return
	}
	for _, rule := range s.Rules {
		if rule.Direction != dir {
			continue
		}
		if !rule.matches(host, ip) {
			continue
		}
		switch rule.Action {
		case Set:
			h.Set(rule.Name, rule.Value)
		case Add:
			h.Add(rule.Name, rule.Value)
		case Remove:
			h.Del(rule.Name)
		case Replace:
			// Only rewrites what is already there, so a rule can normalise a
			// client's header without inventing one it never sent.
			if h.Get(rule.Name) != "" {
				h.Set(rule.Name, rule.Value)
			}
		}
	}
}

// matches reports whether a rule's condition admits a destination.
func (r Rule) matches(host string, ip net.IP) bool {
	if r.Condition == nil {
		return true
	}
	set := &policy.RuleSet{Rules: []policy.Rule{*r.Condition}}
	decision, _ := set.Match(host, ip)
	return decision == policy.Allow
}

// FromMap builds a rule set from the unconditional name/value pairs the older
// configuration used.
//
// Existing rules are the degenerate case of the new form — no condition, action
// set, request direction — so they become rules rather than living alongside a
// second mechanism that would have to be kept in step.
func FromMap(m map[string]string) *RuleSet {
	if len(m) == 0 {
		return nil
	}
	set := &RuleSet{}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	// Sorted so the result is deterministic; a map's order would make the
	// applied set differ between runs for no reason.
	sortStrings(names)
	for _, name := range names {
		canonical := http.CanonicalHeaderKey(name)
		if _, blocked := Forbidden(canonical); blocked {
			// Silently dropped rather than rejected: this path converts
			// configuration that already exists, and refusing to start because
			// of a value somebody set long ago would be a worse outcome than
			// declining to apply it. The parser rejects new ones.
			continue
		}
		set.Rules = append(set.Rules, Rule{
			Direction: Request, Action: Set, Name: canonical, Value: m[name],
		})
	}
	if len(set.Rules) == 0 {
		return nil
	}
	return set
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
