package policy

import (
	"net"
	"strings"
	"testing"
)

func mustClients(t *testing.T, text string) *ClientSet {
	t.Helper()
	set, err := ParseClients(text)
	if err != nil {
		t.Fatalf("ParseClients(%q): %v", text, err)
	}
	return set
}

func TestParseClientRule(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"allow 10.0.0.0/8", "allow 10.0.0.0/8"},
		{"deny 10.1.2.3", "deny 10.1.2.3"},
		{"allow 2001:db8::/32", "allow 2001:db8::/32"},
		{"allow 192.168.0.0/16 { allow domain example.com; deny all }",
			"allow 192.168.0.0/16 { allow domain example.com; deny all }"},
	} {
		got, err := ParseClientRule(tc.in)
		if err != nil {
			t.Errorf("ParseClientRule(%q): %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("ParseClientRule(%q) = %q, want %q", tc.in, got.String(), tc.want)
		}
	}
}

func TestParseClientRuleRejectsNonsense(t *testing.T) {
	for _, in := range []string{
		"", "allow", "maybe 10.0.0.0/8", "allow not-an-address",
		"allow 10.0.0.0/8 extra", "allow 10.0.0.0/8 { allow bogus x }",
		"allow 10.0.0.0/8 { allow domain example.com",
	} {
		if _, err := ParseClientRule(in); err == nil {
			t.Errorf("ParseClientRule(%q) accepted nonsense", in)
		}
	}
}

// The most specific prefix wins regardless of the order entries were written
// in. A client table describes a network; requiring the specific entry to come
// first would make ordering load-bearing and easy to get wrong.
func TestClientMatchPrefersLongestPrefix(t *testing.T) {
	for _, text := range []string{
		"allow 10.0.0.0/8\ndeny 10.1.2.3",
		"deny 10.1.2.3\nallow 10.0.0.0/8", // reversed: same answer
	} {
		set := mustClients(t, text)
		if got, _ := set.Match("10.1.2.3"); got != Deny {
			t.Errorf("%q: host got %v, want Deny", text, got)
		}
		if got, _ := set.Match("10.9.9.9"); got != Allow {
			t.Errorf("%q: sibling got %v, want Allow", text, got)
		}
	}
}

func TestClientDefaults(t *testing.T) {
	// An allowlist: only what is listed may connect.
	allowlist := mustClients(t, "allow 10.0.0.0/8\ndefault deny")
	if got, _ := allowlist.Match("10.1.1.1"); got != Allow {
		t.Errorf("listed client: got %v", got)
	}
	if got, _ := allowlist.Match("203.0.113.1"); got != Deny {
		t.Errorf("unlisted client: got %v, want Deny", got)
	}

	// A denylist: everything except what is listed.
	denylist := mustClients(t, "deny 203.0.113.0/24\ndefault allow")
	if got, _ := denylist.Match("203.0.113.5"); got != Deny {
		t.Errorf("listed client: got %v", got)
	}
	if got, _ := denylist.Match("198.51.100.1"); got != Allow {
		t.Errorf("unlisted client: got %v", got)
	}

	// No default: the table has no opinion about anyone unlisted.
	neutral := mustClients(t, "allow 10.0.0.0/8")
	if got, _ := neutral.Match("203.0.113.1"); got != Undecided {
		t.Errorf("unlisted client: got %v, want Undecided", got)
	}
}

func TestClientDestinationsOverrideGlobal(t *testing.T) {
	global := mustParse(t, "allow all")
	set := mustClients(t, `
		allow 10.0.0.0/8 { allow domain example.com; deny all }
		allow 192.168.0.0/16
	`)

	// A client with its own list uses it.
	scoped := set.DestinationsFor("10.1.2.3", global)
	if got, _ := scoped.Match("elsewhere.test", nil); got != Deny {
		t.Errorf("scoped client: got %v, want Deny", got)
	}
	if got, _ := scoped.Match("api.example.com", nil); got != Allow {
		t.Errorf("scoped client: got %v, want Allow", got)
	}

	// A client without one falls back to the global set.
	if got, _ := set.DestinationsFor("192.168.1.1", global).Match("elsewhere.test", nil); got != Allow {
		t.Errorf("unscoped client: got %v, want the global Allow", got)
	}
	// As does an unlisted client.
	if got, _ := set.DestinationsFor("203.0.113.1", global).Match("elsewhere.test", nil); got != Allow {
		t.Errorf("unlisted client: got %v, want the global Allow", got)
	}
}

func TestClientMatchHandlesUnparseableAddress(t *testing.T) {
	set := mustClients(t, "allow 10.0.0.0/8\ndefault deny")
	// An address that cannot be parsed matches no prefix, so it must fall to
	// the default rather than being guessed either way.
	if got, _ := set.Match("not-an-ip"); got != Deny {
		t.Errorf("got %v, want the default Deny", got)
	}
	if got, _ := set.Match(""); got != Deny {
		t.Errorf("empty: got %v, want the default Deny", got)
	}
}

func TestClientSetRoundTrips(t *testing.T) {
	text := "allow 10.0.0.0/8 { allow domain example.com; deny all }\ndeny 10.1.2.3\ndefault deny"
	set := mustClients(t, text)
	if set.String() != text {
		t.Errorf("round trip:\n got %q\nwant %q", set.String(), text)
	}
	// And parses back to the same decisions.
	again := mustClients(t, set.String())
	if got, _ := again.Match("10.1.2.3"); got != Deny {
		t.Errorf("reparsed: got %v", got)
	}
}

func TestEmptyClientSet(t *testing.T) {
	var nilSet *ClientSet
	if got, _ := nilSet.Match("10.0.0.1"); got != Undecided {
		t.Errorf("nil set: got %v", got)
	}
	if !nilSet.Empty() || !mustClients(t, "").Empty() {
		t.Error("empty sets should report empty")
	}
	// A set that is only a default still constrains.
	if mustClients(t, "default deny").Empty() {
		t.Error("a default-only set is not empty")
	}
}

func TestParseClientsReportsLineNumbers(t *testing.T) {
	_, err := ParseClients("allow 10.0.0.0/8\ndeny 10.1.2.3\nallow bogus")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("want a line-3 error, got %v", err)
	}
}

var _ = net.ParseIP
