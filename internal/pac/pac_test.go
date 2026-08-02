package pac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pod32g/proxy/internal/policy"
)

// pacHelpers implements the standard PAC environment a browser provides.
//
// Executing the generated file against these is what makes this a validation
// rather than a string comparison: asserting the text contains what I expected
// proves only that I wrote what I meant to write, not that a client evaluating
// it reaches the same answer.
const pacHelpers = `
function isPlainHostName(host) { return host.indexOf('.') === -1; }
function dnsDomainIs(host, domain) {
  return host.length >= domain.length &&
         host.substring(host.length - domain.length) === domain;
}
function shExpMatch(str, pattern) {
  pattern = pattern.replace(/\./g, '\\.').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + pattern + '$').test(str);
}
function convertAddr(ip) {
  var p = ip.split('.').map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}
function isInNet(host, pattern, mask) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(host)) return false;
  return (convertAddr(host) & convertAddr(mask)) === (convertAddr(pattern) & convertAddr(mask));
}
function dnsResolve(host) { return null; }
function myIpAddress() { return '127.0.0.1'; }
function localHostOrDomainIs(host, hostdom) { return host === hostdom; }
function isResolvable(host) { return true; }
function dnsDomainLevels(host) { return host.split('.').length - 1; }
`

// evalPAC runs FindProxyForURL for each host under a JavaScript engine and
// returns what it answered.
func evalPAC(t *testing.T, pacBody string, hosts []string) map[string]string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no JavaScript engine available to validate the PAC against")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "run.js")
	hostsJSON, err := json.Marshal(hosts)
	if err != nil {
		t.Fatal(err)
	}

	body := pacHelpers + "\n" + pacBody + "\n" +
		"const hosts = " + string(hostsJSON) + ";\n" +
		"const out = {};\n" +
		"for (const h of hosts) { out[h] = FindProxyForURL('http://' + h + '/', h); }\n" +
		"console.log(JSON.stringify(out));\n"

	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(node, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the generated PAC did not run under a JS engine: %v\n%s\n--- file ---\n%s",
			err, out, pacBody)
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
		t.Fatalf("decoding the PAC result: %v (%s)", err, out)
	}
	return result
}

// The minimal file: everything through the proxy, and nothing about policy.
func TestMinimalPACRoutesEverythingThroughTheProxy(t *testing.T) {
	body := Generate(Config{Address: "proxy.example.com:8080"})

	got := evalPAC(t, body, []string{
		"example.com", "internal.example.com", "10.1.2.3", "localhost",
	})
	for host, answer := range got {
		if !strings.HasPrefix(answer, "PROXY proxy.example.com:8080") {
			t.Errorf("%s -> %q, want the proxy", host, answer)
		}
	}
}

// A bare "PROXY host:port" leaves a client with no network at all when the
// proxy is down. Falling back to DIRECT degrades instead of failing closed.
func TestPACFallsBackToDirect(t *testing.T) {
	body := Generate(Config{Address: "proxy.example.com:8080"})
	got := evalPAC(t, body, []string{"example.com"})
	if !strings.HasSuffix(got["example.com"], "; DIRECT") {
		t.Errorf("got %q, want a DIRECT fallback", got["example.com"])
	}
}

// The disclosure question, asserted rather than asserted-about: with hints off,
// no internal name from the policy may appear in the file at all.
func TestMinimalPACLeaksNothingFromThePolicy(t *testing.T) {
	rules, err := policy.Parse(strings.Join([]string{
		"deny domain secret-project.internal.example.com",
		"deny cidr 10.42.0.0/16",
		"allow all",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}

	body := Generate(Config{
		Address: "proxy.example.com:8080",
		Rules:   rules,
		Bypass:  []string{"private.corp.example.com"},
		// HintDirect deliberately not set.
	})

	for _, secret := range []string{
		"secret-project", "internal.example.com", "10.42", "private.corp",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("the minimal PAC discloses %q:\n%s", secret, body)
		}
	}
}

// And with hints on, the routing is actually better — which is the reason the
// option exists and the reason it is separate.
func TestHintedPACReturnsDirectForRefusedDestinations(t *testing.T) {
	rules, err := policy.Parse("deny domain blocked.example.com\nallow all")
	if err != nil {
		t.Fatal(err)
	}
	body := Generate(Config{
		Address: "proxy.example.com:8080", HintDirect: true, Rules: rules,
	})

	got := evalPAC(t, body, []string{
		"blocked.example.com", "api.blocked.example.com", "allowed.example.com",
	})
	if got["blocked.example.com"] != "DIRECT" {
		t.Errorf("a denied host -> %q, want DIRECT", got["blocked.example.com"])
	}
	if got["api.blocked.example.com"] != "DIRECT" {
		t.Errorf("a denied subdomain -> %q, want DIRECT", got["api.blocked.example.com"])
	}
	if !strings.HasPrefix(got["allowed.example.com"], "PROXY ") {
		t.Errorf("an allowed host -> %q, want the proxy", got["allowed.example.com"])
	}
}

// A deny that sits after an allow may be unreachable for a given host, and a
// PAC cannot express "unless an earlier rule matched". Emitting it anyway would
// route a client direct to somewhere the proxy would have allowed.
func TestOnlyLeadingDenialsBecomeHints(t *testing.T) {
	rules, err := policy.Parse(strings.Join([]string{
		"deny domain first.example.com",
		"allow domain example.com",
		"deny domain later.example.com",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	body := Generate(Config{
		Address: "proxy.example.com:8080", HintDirect: true, Rules: rules,
	})

	if !strings.Contains(body, "first.example.com") {
		t.Error("a leading denial was not hinted")
	}
	if strings.Contains(body, "later.example.com") {
		t.Error("a denial behind an allow was hinted; the allow may win for that host")
	}

	got := evalPAC(t, body, []string{"first.example.com", "later.example.com"})
	if got["first.example.com"] != "DIRECT" {
		t.Errorf("first -> %q", got["first.example.com"])
	}
	if !strings.HasPrefix(got["later.example.com"], "PROXY ") {
		t.Errorf("later -> %q, want the proxy so the policy decides", got["later.example.com"])
	}
}

func TestHintedPACHonoursTheBypassList(t *testing.T) {
	body := Generate(Config{
		Address: "proxy.example.com:8080", HintDirect: true,
		Bypass: []string{"internal.example.com", "10.0.0.0/8", ".corp.test"},
	})

	got := evalPAC(t, body, []string{
		"internal.example.com", "api.internal.example.com",
		"10.1.2.3", "11.1.2.3", "host.corp.test", "example.com",
	})
	for _, direct := range []string{
		"internal.example.com", "api.internal.example.com", "10.1.2.3", "host.corp.test",
	} {
		if got[direct] != "DIRECT" {
			t.Errorf("%s -> %q, want DIRECT", direct, got[direct])
		}
	}
	for _, proxied := range []string{"11.1.2.3", "example.com"} {
		if !strings.HasPrefix(got[proxied], "PROXY ") {
			t.Errorf("%s -> %q, want the proxy", proxied, got[proxied])
		}
	}
}

// Loopback and unqualified names are always direct with hints on: proxying them
// is a round trip that cannot succeed.
func TestHintedPACSendsLoopbackDirect(t *testing.T) {
	body := Generate(Config{Address: "proxy.example.com:8080", HintDirect: true})
	got := evalPAC(t, body, []string{"localhost", "127.0.0.1", "intranet", "example.com"})

	for _, direct := range []string{"localhost", "127.0.0.1", "intranet"} {
		if got[direct] != "DIRECT" {
			t.Errorf("%s -> %q, want DIRECT", direct, got[direct])
		}
	}
	if !strings.HasPrefix(got["example.com"], "PROXY ") {
		t.Errorf("example.com -> %q", got["example.com"])
	}
}

// "deny all" at the head means nothing is proxyable, which a PAC can say
// plainly rather than sending every client on a round trip to a 403.
func TestDenyAllBecomesDirect(t *testing.T) {
	rules, err := policy.Parse("deny all")
	if err != nil {
		t.Fatal(err)
	}
	body := Generate(Config{Address: "proxy.example.com:8080", HintDirect: true, Rules: rules})
	got := evalPAC(t, body, []string{"example.com"})
	if got["example.com"] != "DIRECT" {
		t.Errorf("got %q, want DIRECT", got["example.com"])
	}
}

// A generated program must not be one quoting mistake away from arbitrary
// script running in every client that fetches it.
//
// Asserted by running it: a breakout would either fail to parse or execute the
// injected statement, and neither shows up in a substring check of the text —
// the escaped form contains the same characters as the unescaped one.
func TestAddressIsEscaped(t *testing.T) {
	const hostile = `evil"; alert(1); //`
	body := Generate(Config{Address: hostile})

	got := evalPAC(t, body, []string{"example.com"})
	answer := got["example.com"]

	// The whole hostile string has to come back as data inside the result.
	if !strings.Contains(answer, hostile) {
		t.Errorf("result = %q, want the address carried through as a literal", answer)
	}
	// alert is not defined in the PAC environment, so had the quote escaped its
	// literal the script would have failed to run at all — evalPAC would have
	// reported it. Assert the shape too, so a future change that makes the
	// engine tolerant does not hide a breakout.
	if !strings.HasPrefix(answer, "PROXY ") || !strings.HasSuffix(answer, "; DIRECT") {
		t.Errorf("result = %q, want a well-formed PAC answer", answer)
	}
}

// Regenerated per request, so it cannot drift from the policy it describes.
func TestHandlerReflectsLiveConfiguration(t *testing.T) {
	addr := "first.example.com:8080"
	h := Handler(func() Config { return Config{Address: addr} })

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest("GET", Path, nil))
	if !strings.Contains(first.Body.String(), "first.example.com:8080") {
		t.Fatalf("body = %q", first.Body.String())
	}
	if ct := first.Header().Get("Content-Type"); ct != ContentType {
		t.Errorf("Content-Type = %q, want %q", ct, ContentType)
	}
	// Clients cache these aggressively, and a stale one routes by a policy that
	// no longer exists.
	if cc := first.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	addr = "second.example.com:9090"
	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest("GET", Path, nil))
	if !strings.Contains(second.Body.String(), "second.example.com:9090") {
		t.Errorf("the handler served a stale file: %q", second.Body.String())
	}
}

func TestHandlerIsReadOnly(t *testing.T) {
	h := Handler(func() Config { return Config{Address: "proxy:8080"} })
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, Path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s returned %d, want 405", method, rec.Code)
		}
	}
}

// A PAC advertising a wildcard bind address is a file that cannot work, and the
// failure surfaces at the client with nothing pointing back here.
func TestAdvertisableRejectsUnreachableAddresses(t *testing.T) {
	for addr, wantOK := range map[string]bool{
		"proxy.example.com:8080": true,
		"10.0.0.5:8080":          true,
		"0.0.0.0:8080":           false,
		"[::]:8080":              false,
		":8080":                  false,
		"proxy.example.com":      false,
	} {
		ok, why := Advertisable(addr)
		if ok != wantOK {
			t.Errorf("Advertisable(%q) = %v (%s), want %v", addr, ok, why, wantOK)
		}
		if !ok && why == "" {
			t.Errorf("Advertisable(%q) refused without saying why", addr)
		}
	}
}
