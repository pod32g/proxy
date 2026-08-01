package policy

import (
	"net"
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) *RuleSet {
	t.Helper()
	set, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return set
}

func TestParseRule(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"allow domain example.com", "allow domain example.com"},
		{"deny  cidr  10.0.0.0/8", "deny cidr 10.0.0.0/8"},
		{"DENY ALL", "deny all"},
		{"allow cidr 203.0.113.5", "allow cidr 203.0.113.5"}, // bare address is a host rule
		{"allow domain *.example.com", "allow domain *.example.com"},
	} {
		got, err := ParseRule(tc.in)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("ParseRule(%q) = %q, want %q", tc.in, got.String(), tc.want)
		}
	}
}

func TestParseRuleRejectsNonsense(t *testing.T) {
	for _, in := range []string{
		"", "allow", "maybe domain example.com", "allow subnet 10.0.0.0/8",
		"allow cidr not-a-network", "allow all extra", "allow domain", "allow cidr 10.0.0.0/33",
	} {
		if _, err := ParseRule(in); err == nil {
			t.Errorf("ParseRule(%q) accepted nonsense", in)
		}
	}
	// The error must quote the offending line: in an ordered list, knowing
	// which rule failed is most of the diagnosis.
	_, err := ParseRule("allow subnet 10.0.0.0/8")
	if !strings.Contains(err.Error(), "subnet") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

func TestParseSkipsBlanksAndComments(t *testing.T) {
	set := mustParse(t, "# a comment\n\nallow domain example.com\n   \n# another\ndeny all\n")
	if len(set.Rules) != 2 {
		t.Fatalf("got %d rules, want 2: %v", len(set.Rules), set.Rules)
	}
	if set.String() != "allow domain example.com\ndeny all" {
		t.Errorf("round trip: %q", set.String())
	}
}

func TestParseReportsLineNumbers(t *testing.T) {
	_, err := Parse("allow domain example.com\ndeny all\nallow bogus x")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("want a line-3 error, got %v", err)
	}
}

func TestMatchDomain(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "api.example.com", true}, // bare pattern covers subdomains
		{"example.com", "notexample.com", false}, // and only on a label boundary
		{"example.com", "example.com.evil.test", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false}, // apex excluded deliberately
		{"*", "anything.test", true},
		{"EXAMPLE.com", "api.Example.COM", true}, // case-insensitive
		{"example.com.", "example.com", true},    // trailing dot ignored
	} {
		if got := matchDomain(tc.pattern, tc.host); got != tc.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestMatchIsFirstMatchWins(t *testing.T) {
	set := mustParse(t, `
		deny  domain internal.example.com
		allow domain example.com
		deny  all
	`)
	for _, tc := range []struct {
		host string
		want Decision
	}{
		{"internal.example.com", Deny}, // specific deny precedes the broad allow
		{"api.example.com", Allow},
		{"example.com", Allow},
		{"elsewhere.test", Deny}, // falls through to deny all
	} {
		got, _ := set.Match(tc.host, nil)
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.host, got, tc.want)
		}
	}
}

// The ordering hazard this design exists for: evaluating domain and CIDR rules
// in separate passes would let "deny all" answer for a host whose address an
// earlier CIDR rule allows.
func TestPreDNSEvaluationDefersAtFirstCIDRRule(t *testing.T) {
	set := mustParse(t, "allow cidr 10.0.0.0/8\ndeny all")

	// Without an address there is no honest answer, so it must not guess.
	if got, _ := set.Match("host.test", nil); got != Undecided {
		t.Fatalf("pre-DNS: got %v, want Undecided", got)
	}
	// With the address, the ordered list decides properly.
	if got, _ := set.Match("host.test", net.ParseIP("10.1.2.3")); got != Allow {
		t.Errorf("in-range address: got %v, want Allow", got)
	}
	if got, _ := set.Match("host.test", net.ParseIP("203.0.113.1")); got != Deny {
		t.Errorf("out-of-range address: got %v, want Deny", got)
	}
}

// A determinate match before any CIDR rule may still decide early, so obvious
// denials cost neither a DNS lookup nor a dial.
func TestPreDNSDecidesWhenUnambiguous(t *testing.T) {
	set := mustParse(t, "deny domain blocked.test\nallow cidr 10.0.0.0/8\ndeny all")
	if got, _ := set.Match("blocked.test", nil); got != Deny {
		t.Errorf("got %v, want an early Deny", got)
	}
	if got, _ := set.Match("other.test", nil); got != Undecided {
		t.Errorf("got %v, want Undecided — a CIDR rule is in the way", got)
	}
}

func TestMatchCIDR(t *testing.T) {
	set := mustParse(t, "deny cidr 192.168.0.0/16\nallow cidr 2001:db8::/32\ndeny all")
	for _, tc := range []struct {
		ip   string
		want Decision
	}{
		{"192.168.1.1", Deny},
		{"2001:db8::1", Allow},
		{"203.0.113.1", Deny},
	} {
		got, _ := set.Match("host.test", net.ParseIP(tc.ip))
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestMatchReturnsTheResponsibleRule(t *testing.T) {
	set := mustParse(t, "allow domain example.com\ndeny all")
	_, rule := set.Match("api.example.com", nil)
	if rule == nil || rule.String() != "allow domain example.com" {
		t.Fatalf("got %v, want the matching rule reported", rule)
	}
	// Knowing which rule fired is what makes an ordered list debuggable.
	_, rule = set.Match("other.test", nil)
	if rule == nil || rule.String() != "deny all" {
		t.Fatalf("got %v, want the deny-all rule", rule)
	}
}

func TestEmptySetHasNoOpinion(t *testing.T) {
	var nilSet *RuleSet
	if got, _ := nilSet.Match("example.com", nil); got != Undecided {
		t.Errorf("nil set: got %v", got)
	}
	if !nilSet.Empty() {
		t.Error("nil set should be empty")
	}
	set := mustParse(t, "")
	if got, _ := set.Match("example.com", nil); got != Undecided {
		t.Errorf("empty set: got %v", got)
	}
	if !set.Empty() {
		t.Error("parsed-empty set should be empty")
	}
}
