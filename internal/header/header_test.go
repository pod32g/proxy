package header

import (
	"net/http"
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
	for _, tc := range []struct {
		in     string
		action Action
		dir    Direction
		name   string
		value  string
		cond   bool
	}{
		{"set X-A: 1", Set, Request, "X-A", "1", false},
		{"add X-A: 1", Add, Request, "X-A", "1", false},
		{"remove X-A", Remove, Request, "X-A", "", false},
		{"replace User-Agent: proxy", Replace, Request, "User-Agent", "proxy", false},
		{"response set X-Via: proxy", Set, Response, "X-Via", "proxy", false},
		{"SET x-a: 1", Set, Request, "X-A", "1", false},
		{"set X-A: 1 for domain example.com", Set, Request, "X-A", "1", true},
		{"remove X-A for all", Remove, Request, "X-A", "", true},
		{"request set X-A: 1", Set, Request, "X-A", "1", false},
	} {
		got, err := ParseRule(tc.in)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tc.in, err)
			continue
		}
		if got.Action != tc.action || got.Direction != tc.dir ||
			got.Name != tc.name || got.Value != tc.value || (got.Condition != nil) != tc.cond {
			t.Errorf("ParseRule(%q) = %+v", tc.in, got)
		}
	}
}

// A trailing "for" with nothing after it is a value, not a truncated condition.
//
// The alternative — rejecting it as malformed — would refuse a legitimate value
// that happens to end in that word. A header value is opaque data and the parser
// should not second-guess it; the condition marker requires something after it,
// which makes the split unambiguous in the only direction that matters.
func TestTrailingForIsPartOfTheValue(t *testing.T) {
	r, err := ParseRule("set X-A: 1 for")
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if r.Value != "1 for" {
		t.Errorf("value = %q, want %q", r.Value, "1 for")
	}
	if r.Condition != nil {
		t.Error("a trailing \"for\" was read as a condition")
	}
}

// A header value may contain the word "for", so the condition has to be taken
// from the end rather than by splitting on the first occurrence.
func TestConditionIsTakenFromTheEnd(t *testing.T) {
	r, err := ParseRule("set X-Note: this is for you for domain example.com")
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if r.Value != "this is for you" {
		t.Errorf("value = %q, want the whole value including \"for\"", r.Value)
	}
	if r.Condition == nil {
		t.Fatal("condition not parsed")
	}
}

func TestParseRejectsNonsense(t *testing.T) {
	for _, in := range []string{
		"", "set", "shout X-A: 1", "set : 1", "set X-A", "remove X-A: 1",
		"set X-A: 1 for subnet 10.0.0.0/8", "set X-A(bad): 1",
		// A cidr condition can never be evaluated where headers are applied.
		"set X-A: 1 for cidr 10.0.0.0/8",
	} {
		if _, err := ParseRule(in); err == nil {
			t.Errorf("ParseRule(%q) accepted nonsense", in)
		}
	}
}

// A newline in a value is response splitting: it ends the header and starts
// whatever the author wants next.
func TestControlCharactersAreRejected(t *testing.T) {
	for _, in := range []string{
		"set X-A: one\ntwo",
		"set X-A: one\rtwo",
		"set X-A: one\x00two",
	} {
		if _, err := ParseRule(in); err == nil {
			t.Errorf("ParseRule(%q) accepted a control character", in)
		}
	}
}

// The criterion: rules cannot re-add the hop-by-hop headers PROXY-6 strips, or
// the RFC compliance and the credential leak it fixed come straight back.
func TestHopByHopHeadersCannotBeSet(t *testing.T) {
	for _, name := range []string{
		"Proxy-Authorization", "proxy-authorization", "PROXY-AUTHORIZATION",
		"Proxy-Authenticate", "Proxy-Connection", "Keep-Alive",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"Content-Length",
	} {
		for _, action := range []string{"set", "add", "replace"} {
			rule := action + " " + name + ": x"
			if _, err := ParseRule(rule); err == nil {
				t.Errorf("ParseRule(%q) allowed a hop-by-hop header", rule)
			}
		}
		if _, err := ParseRule("remove " + name); err == nil {
			t.Errorf("remove %s was allowed", name)
		}
	}
}

// Connection is the lever that is easy to miss: it is how a sender extends the
// hop-by-hop set, so allowing a rule on it would let any header be made
// per-hop. Blocking only the named headers leaves this open.
func TestConnectionHeaderCannotBeSet(t *testing.T) {
	_, err := ParseRule("set Connection: X-Secret")
	if err == nil {
		t.Fatal("a rule was allowed to rewrite Connection")
	}
	if !strings.Contains(err.Error(), "hop-by-hop") {
		t.Errorf("error does not explain why: %v", err)
	}
}

// The same class of bug pointed the other way: PROXY-6 strips hop-by-hop in
// both directions, so a response rule must be blocked too.
func TestHopByHopBlockedOnResponsesToo(t *testing.T) {
	for _, rule := range []string{
		"response set Proxy-Authenticate: Basic",
		"response set Connection: X-Secret",
		"response set Transfer-Encoding: chunked",
	} {
		if _, err := ParseRule(rule); err == nil {
			t.Errorf("ParseRule(%q) allowed a hop-by-hop header on a response", rule)
		}
	}
}

func TestApplyActions(t *testing.T) {
	set := mustParse(t, `
		set X-Set: new
		add X-List: second
		remove X-Gone
		replace X-Present: rewritten
		replace X-Absent: never
	`)

	h := http.Header{}
	h.Set("X-Set", "old")
	h.Set("X-List", "first")
	h.Set("X-Gone", "still here")
	h.Set("X-Present", "original")

	set.Apply(h, Request, "example.com", nil)

	if got := h.Get("X-Set"); got != "new" {
		t.Errorf("set: %q", got)
	}
	if got := h.Values("X-List"); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("add: %v — add must keep what was there, unlike set", got)
	}
	if _, still := h["X-Gone"]; still {
		t.Error("remove left the header in place")
	}
	if got := h.Get("X-Present"); got != "rewritten" {
		t.Errorf("replace on a present header: %q", got)
	}
	// replace must not invent a header the client never sent.
	if _, invented := h["X-Absent"]; invented {
		t.Error("replace created a header that was not present")
	}
}

// A cidr condition is rejected where it is written rather than accepted and
// silently never matched: headers are set before the destination is resolved,
// so the address the condition needs does not exist yet.
func TestCIDRConditionsAreRejectedWithAnExplanation(t *testing.T) {
	_, err := ParseRule("set X-A: 1 for cidr 10.0.0.0/8")
	if err == nil {
		t.Fatal("a cidr condition was accepted; it could never have matched")
	}
	if !strings.Contains(err.Error(), "before the destination is resolved") {
		t.Errorf("error does not say why: %v", err)
	}
	if !strings.Contains(err.Error(), "domain") {
		t.Errorf("error does not point at the alternative: %v", err)
	}
}

func TestConditionsLimitByDestination(t *testing.T) {
	set := mustParse(t, `
		set X-Internal: 1 for domain internal.example.com
		set X-Wildcard: 1 for domain *.example.org
		set X-Always: 1
	`)

	t.Run("matching domain", func(t *testing.T) {
		h := http.Header{}
		set.Apply(h, Request, "internal.example.com", nil)
		if h.Get("X-Internal") != "1" || h.Get("X-Always") != "1" {
			t.Errorf("got %v", h)
		}
	})

	t.Run("other domain", func(t *testing.T) {
		h := http.Header{}
		set.Apply(h, Request, "example.org", nil)
		if h.Get("X-Internal") != "" {
			t.Error("a conditional rule fired for a non-matching destination")
		}
		if h.Get("X-Always") != "1" {
			t.Error("an unconditional rule did not fire")
		}
	})

	t.Run("wildcard domain", func(t *testing.T) {
		h := http.Header{}
		set.Apply(h, Request, "api.example.org", nil)
		if h.Get("X-Wildcard") != "1" {
			t.Error("a wildcard domain condition did not match a subdomain")
		}
	})

	t.Run("wildcard excludes the apex", func(t *testing.T) {
		h := http.Header{}
		set.Apply(h, Request, "example.org", nil)
		if h.Get("X-Wildcard") != "" {
			t.Error("*.example.org matched the apex")
		}
	})
}

func TestDirectionsAreSeparate(t *testing.T) {
	set := mustParse(t, "set X-Req: 1\nresponse set X-Resp: 1")

	req := http.Header{}
	set.Apply(req, Request, "example.com", nil)
	if req.Get("X-Req") != "1" || req.Get("X-Resp") != "" {
		t.Errorf("request headers = %v", req)
	}

	resp := http.Header{}
	set.Apply(resp, Response, "example.com", nil)
	if resp.Get("X-Resp") != "1" || resp.Get("X-Req") != "" {
		t.Errorf("response headers = %v", resp)
	}
}

// Later wins, which is what makes a general rule followed by a specific
// exception behave the way it reads.
func TestOrderIsAsWritten(t *testing.T) {
	set := mustParse(t, "set X-A: general\nset X-A: specific for domain example.com")

	h := http.Header{}
	set.Apply(h, Request, "example.com", nil)
	if got := h.Get("X-A"); got != "specific" {
		t.Errorf("got %q, want the later rule to win", got)
	}

	other := http.Header{}
	set.Apply(other, Request, "elsewhere.test", nil)
	if got := other.Get("X-A"); got != "general" {
		t.Errorf("got %q, want the general rule for a non-matching host", got)
	}
}

// The criterion: existing unconditional rules keep working and migrate
// automatically rather than living alongside a second mechanism.
func TestFromMapMigratesExistingRules(t *testing.T) {
	set := FromMap(map[string]string{"X-A": "1", "x-b": "2"})
	if set == nil || len(set.Rules) != 2 {
		t.Fatalf("got %v", set)
	}
	h := http.Header{}
	set.Apply(h, Request, "anywhere.test", nil)
	if h.Get("X-A") != "1" || h.Get("X-B") != "2" {
		t.Errorf("migrated rules did not apply: %v", h)
	}
	// Deterministic: a map's iteration order would otherwise make the rendered
	// set differ between runs for no reason.
	if got := set.String(); got != "set X-A: 1\nset X-B: 2" {
		t.Errorf("String() = %q", got)
	}
}

// Converting configuration that already exists must not refuse to start over a
// value somebody set long ago. New rules are rejected; old ones are dropped.
func TestFromMapDropsForbiddenHeadersInsteadOfFailing(t *testing.T) {
	set := FromMap(map[string]string{"Proxy-Authorization": "Basic x", "X-Fine": "1"})
	if set == nil {
		t.Fatal("everything was dropped")
	}
	h := http.Header{}
	set.Apply(h, Request, "anywhere.test", nil)
	if h.Get("Proxy-Authorization") != "" {
		t.Error("a hop-by-hop header survived migration")
	}
	if h.Get("X-Fine") != "1" {
		t.Error("a valid header was dropped alongside it")
	}
}

func TestRoundTrip(t *testing.T) {
	in := "set X-A: 1\nremove X-B\nreplace X-C: 2 for domain example.com\nresponse set X-D: 3"
	set := mustParse(t, in)
	if got := set.String(); got != in {
		t.Errorf("round trip:\n got %q\nwant %q", got, in)
	}
	if _, err := Parse(set.String()); err != nil {
		t.Errorf("re-parse: %v", err)
	}
}

func TestEmptyAndNilAreHarmless(t *testing.T) {
	var nilSet *RuleSet
	if !nilSet.Empty() {
		t.Error("nil set should be empty")
	}
	nilSet.Apply(http.Header{}, Request, "x", nil)
	if !mustParse(t, "# just a comment\n").Empty() {
		t.Error("comment-only set should be empty")
	}
	mustParse(t, "set X-A: 1").Apply(nil, Request, "x", nil)
}

func TestParseReportsLineNumbers(t *testing.T) {
	_, err := Parse("set X-A: 1\n# fine\nshout X-B: 2")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("want a line-3 error, got %v", err)
	}
}
