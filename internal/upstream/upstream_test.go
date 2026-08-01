package upstream

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw, noProxy string) *Proxy {
	t.Helper()
	p, err := Parse(raw, noProxy)
	if err != nil {
		t.Fatalf("Parse(%q, %q): %v", raw, noProxy, err)
	}
	return p
}

func TestNoParentConfigured(t *testing.T) {
	p := mustParse(t, "", "")
	if p.Configured() {
		t.Error("an empty URL produced a configured parent")
	}
	// With no parent everything is direct, which every caller reads as "bypass".
	if !p.Bypass("example.com:443") {
		t.Error("with no parent, destinations must be reached directly")
	}
	if p.AuthHeader() != "" || p.String() != "" || p.Addr() != "" {
		t.Error("an unconfigured parent produced values")
	}
}

// Credentials in the URL are what people paste from an existing http_proxy
// setting, but they must not stay there: the URL is logged and persisted, and a
// credential embedded in it would travel everywhere it goes.
func TestCredentialsAreLiftedOutOfTheURL(t *testing.T) {
	p := mustParse(t, "http://user:hunter2@proxy.corp:3128", "")
	if p.Username != "user" || p.Password != "hunter2" {
		t.Errorf("credentials = %q/%q", p.Username, p.Password)
	}
	if strings.Contains(p.String(), "hunter2") || strings.Contains(p.String(), "user") {
		t.Errorf("String() = %q, want the credentials stripped", p.String())
	}
	if got, want := p.AuthHeader(), "Basic dXNlcjpodW50ZXIy"; got != want {
		t.Errorf("AuthHeader() = %q, want %q", got, want)
	}
}

func TestParseRejectsUnusableURLs(t *testing.T) {
	for _, raw := range []string{
		"proxy.corp:3128",     // no scheme: parses to something unusable
		"socks5://proxy:1080", // unsupported
		"http://",             // no host
	} {
		if _, err := Parse(raw, ""); err == nil {
			t.Errorf("Parse(%q) accepted an unusable parent", raw)
		}
	}
}

// A bare host:port is the most likely thing somebody types, and it parses in Go
// as a scheme with an opaque body — producing a parent that is silently never
// used. The error has to point at the fix.
func TestMissingSchemeErrorSuggestsTheFix(t *testing.T) {
	_, err := Parse("proxy.corp:3128", "")
	if err == nil {
		t.Fatal("accepted a schemeless parent")
	}
	if !strings.Contains(err.Error(), "http://proxy.corp:3128") {
		t.Errorf("error does not suggest the corrected form: %v", err)
	}
}

func TestAddrDefaultsThePort(t *testing.T) {
	for raw, want := range map[string]string{
		"http://proxy.corp:3128": "proxy.corp:3128",
		"http://proxy.corp":      "proxy.corp:80",
		"https://proxy.corp":     "proxy.corp:443",
	} {
		if got := mustParse(t, raw, "").Addr(); got != want {
			t.Errorf("Addr(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestBypass(t *testing.T) {
	p := mustParse(t, "http://proxy.corp:3128",
		"internal.example.com, .corp.test, 10.0.0.0/8, localhost")

	for hostport, want := range map[string]bool{
		"internal.example.com:443":     true,  // exact
		"api.internal.example.com:443": true,  // subdomain
		"notinternal.example.com:443":  false, // only on a label boundary
		"host.corp.test:80":            true,  // leading-dot spelling
		"corp.test:80":                 true,
		"10.1.2.3:443":                 true, // CIDR
		"11.1.2.3:443":                 false,
		"localhost:8080":               true,
		"example.com:443":              false,
		"example.com":                  false, // no port is also a valid form
	} {
		if got := p.Bypass(hostport); got != want {
			t.Errorf("Bypass(%q) = %v, want %v", hostport, got, want)
		}
	}
}

// "*" is the NO_PROXY spelling for "never use the parent", and honouring it
// matters: it is how somebody turns the parent off without editing the URL.
func TestBypassWildcard(t *testing.T) {
	p := mustParse(t, "http://proxy.corp:3128", "*")
	if !p.Bypass("anything.test:443") {
		t.Error("* did not bypass everything")
	}
}

func TestBypassIsCaseInsensitiveAndIgnoresTrailingDots(t *testing.T) {
	p := mustParse(t, "http://proxy.corp:3128", "Internal.Example.COM")
	for _, host := range []string{
		"internal.example.com:443",
		"INTERNAL.EXAMPLE.COM:443",
		"internal.example.com.:443",
	} {
		if !p.Bypass(host) {
			t.Errorf("Bypass(%q) = false", host)
		}
	}
}

func TestBypassListRoundTrips(t *testing.T) {
	in := "internal.example.com,10.0.0.0/8,*"
	p := mustParse(t, "http://proxy.corp:3128", in)
	if got := p.BypassList(); got != in {
		t.Errorf("BypassList() = %q, want %q", got, in)
	}
	// And re-parsing the rendered form gives the same behaviour.
	again := mustParse(t, "http://proxy.corp:3128", p.BypassList())
	if !again.Bypass("api.internal.example.com:443") {
		t.Error("a round-tripped bypass list lost an entry")
	}
}

func TestAuthHeaderOmittedWithoutAUsername(t *testing.T) {
	if got := mustParse(t, "http://proxy.corp:3128", "").AuthHeader(); got != "" {
		t.Errorf("AuthHeader() = %q with no credentials", got)
	}
}

func TestSetCredentials(t *testing.T) {
	p := mustParse(t, "http://proxy.corp:3128", "")
	p.SetCredentials("u", "p")
	if p.Username != "u" || p.Password != "p" {
		t.Errorf("got %q/%q", p.Username, p.Password)
	}
	// Still absent from the rendered URL, which is what gets persisted.
	if strings.Contains(p.String(), "u:p") {
		t.Errorf("String() = %q", p.String())
	}
}

func TestNilProxyIsHarmless(t *testing.T) {
	var p *Proxy
	if p.Configured() {
		t.Error("nil reported as configured")
	}
	if !p.Bypass("example.com:443") {
		t.Error("nil should mean everything is direct")
	}
	if p.String() != "" || p.Addr() != "" || p.AuthHeader() != "" || p.BypassList() != "" {
		t.Error("nil produced values")
	}
}
