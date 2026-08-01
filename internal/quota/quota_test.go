package quota

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) *Set {
	t.Helper()
	set, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return set
}

func TestParseRates(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want float64
	}{
		{"global requests 100/s", 100},
		{"global requests 60/m", 1},
		{"global requests 3600/h", 1},
		{"global requests 1.5/s", 1.5},
	} {
		set := mustParse(t, tc.in)
		if got := set.Global.Requests.PerSecond; got != tc.want {
			t.Errorf("%q: got %v/s, want %v/s", tc.in, got, tc.want)
		}
	}
}

func TestParseSizeSuffixes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want float64
	}{
		{"global bytes 1KB/s", 1e3},
		{"global bytes 1KiB/s", 1024},
		{"global bytes 10MB/s", 1e7},
		{"global bytes 1MiB/s", 1 << 20},
		{"global bytes 2GB/s", 2e9},
		{"global bytes 1024/s", 1024},
	} {
		set := mustParse(t, tc.in)
		if got := set.Global.Bytes.PerSecond; got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A size suffix on a request count means the operator has confused the two
// quotas, and silently reading "10MB" as ten million requests would hide it.
func TestSizeSuffixOnRequestsIsRejected(t *testing.T) {
	_, err := Parse("global requests 10MB/s")
	if err == nil {
		t.Fatal("accepted a size suffix on a request quota")
	}
	if !strings.Contains(err.Error(), "byte quotas") {
		t.Errorf("error does not explain the problem: %v", err)
	}
}

func TestParseBurst(t *testing.T) {
	set := mustParse(t, "global requests 100/s burst 250")
	if set.Global.Requests.Burst != 250 {
		t.Errorf("burst = %v, want 250", set.Global.Requests.Burst)
	}
	set = mustParse(t, "client bytes 1MB/s burst 5MB")
	if set.ClientDefault.Bytes.Burst != 5e6 {
		t.Errorf("burst = %v, want 5e6", set.ClientDefault.Bytes.Burst)
	}
}

// A burst below the rate silently caps throughput below the rate that was
// asked for, which is the opposite of what "burst" suggests.
func TestBurstBelowRateIsRejected(t *testing.T) {
	if _, err := Parse("global requests 100/s burst 10"); err == nil {
		t.Fatal("accepted a burst smaller than the rate")
	}
}

func TestUnlimitedIsExplicit(t *testing.T) {
	set := mustParse(t, "client requests 10/s\nclient 10.1.2.3 requests unlimited")
	if got := set.For("10.9.9.9").Requests; got.Unlimited() {
		t.Error("default client should be limited")
	}
	if got := set.For("10.1.2.3").Requests; !got.Unlimited() {
		t.Errorf("override should be unlimited, got %v", got)
	}
}

func TestParseRejectsNonsense(t *testing.T) {
	for _, in := range []string{
		"global", "global requests", "maybe requests 10/s", "global widgets 10/s",
		"global requests 10", "global requests 10/x", "global requests abc/s",
		"client 10.0.0.0/8", "client not-an-address requests 10/s",
		"global requests 0/s", "global requests -5/s",
		"global requests 10/s burst", "global requests 10/s extra 20",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted nonsense", in)
		}
	}
}

func TestParseReportsLineNumbers(t *testing.T) {
	_, err := Parse("global requests 10/s\n# fine\nclient bogus")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("want a line-3 error, got %v", err)
	}
}

func TestParseSkipsBlanksAndComments(t *testing.T) {
	set := mustParse(t, "# comment\n\n  \nglobal requests 10/s\n")
	if set.Global.Requests.PerSecond != 10 {
		t.Errorf("got %v", set.Global.Requests.PerSecond)
	}
}

func TestLongestPrefixWins(t *testing.T) {
	set := mustParse(t, `
		client requests 5/s
		client 10.0.0.0/8 requests 50/s
		client 10.1.0.0/16 requests 500/s
	`)
	for _, tc := range []struct {
		ip   string
		want float64
	}{
		{"203.0.113.1", 5}, // no override, falls back to the default
		{"10.9.9.9", 50},   // /8
		{"10.1.2.3", 500},  // /16 beats /8 regardless of order
	} {
		if got := set.For(tc.ip).Requests.PerSecond; got != tc.want {
			t.Errorf("%s: got %v/s, want %v/s", tc.ip, got, tc.want)
		}
	}
}

// An override that names only one quota keeps the other from the default.
// Reading "override the request rate" as "and drop the byte limit" would be a
// quiet way to hand someone unlimited bandwidth.
func TestOverrideInheritsUnsetFields(t *testing.T) {
	set := mustParse(t, "client requests 5/s\nclient bytes 1MB/s\nclient 10.0.0.0/8 requests 50/s")
	spec := set.For("10.1.2.3")
	if spec.Requests.PerSecond != 50 {
		t.Errorf("requests = %v, want 50", spec.Requests.PerSecond)
	}
	if spec.Bytes.PerSecond != 1e6 {
		t.Errorf("bytes = %v, want the inherited 1e6", spec.Bytes.PerSecond)
	}
}

func TestRepeatedLinesForOneRangeAccumulate(t *testing.T) {
	set := mustParse(t, "client 10.0.0.0/8 requests 50/s\nclient 10.0.0.0/8 bytes 2MB/s")
	if n := len(set.Clients); n != 1 {
		t.Fatalf("got %d entries, want them merged into 1", n)
	}
	spec := set.For("10.1.2.3")
	if spec.Requests.PerSecond != 50 || spec.Bytes.PerSecond != 2e6 {
		t.Errorf("got %+v", spec)
	}
}

func TestRoundTrip(t *testing.T) {
	// The text is kept as written so a rule set survives the store and the UI
	// without turning "10MB/s" into "1e+07/s".
	in := "global requests 500/s burst 1000\nclient bytes 10MB/s\nclient 10.0.0.0/8 requests 200/s"
	set := mustParse(t, in)
	if got := set.String(); got != in {
		t.Errorf("round trip:\n got %q\nwant %q", got, in)
	}
	if _, err := Parse(set.String()); err != nil {
		t.Errorf("re-parse: %v", err)
	}
}

func TestEmptySetHasNoOpinion(t *testing.T) {
	var nilSet *Set
	if !nilSet.Empty() {
		t.Error("nil set should be empty")
	}
	if !mustParse(t, "").Empty() {
		t.Error("parsed-empty set should be empty")
	}
	if !mustParse(t, "# only a comment").Empty() {
		t.Error("comment-only set should be empty")
	}
}

func TestBareAddressIsAHostEntry(t *testing.T) {
	set := mustParse(t, "client requests 5/s\nclient 10.1.2.3 requests 99/s")
	if got := set.For("10.1.2.3").Requests.PerSecond; got != 99 {
		t.Errorf("got %v, want 99", got)
	}
	if got := set.For("10.1.2.4").Requests.PerSecond; got != 5 {
		t.Errorf("neighbour got %v, want the default 5", got)
	}
}

func TestIPv6Overrides(t *testing.T) {
	set := mustParse(t, "client requests 5/s\nclient 2001:db8::/32 requests 42/s")
	if got := set.For("2001:db8::1").Requests.PerSecond; got != 42 {
		t.Errorf("got %v, want 42", got)
	}
}
