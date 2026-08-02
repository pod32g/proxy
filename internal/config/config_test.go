package config

import (
	"net/http"

	"github.com/pod32g/proxy/internal/header"
	"strings"
	"testing"

	"github.com/pod32g/proxy/internal/policy"
	log "github.com/pod32g/simple-logger"
)

func TestHeaderManagement(t *testing.T) {
	cfg := &Config{}
	cfg.SetHeader("A", "1")
	cfg.SetClientHeader("client1", "B", "2")
	hdrs := cfg.GetHeadersForClient("client1")
	if hdrs["A"] != "1" || hdrs["B"] != "2" {
		t.Fatalf("unexpected headers: %#v", hdrs)
	}
	cfg.DeleteClientHeader("client1", "B")
	hdrs = cfg.GetHeadersForClient("client1")
	if _, ok := hdrs["B"]; ok {
		t.Fatalf("client header not deleted")
	}
	cfg.DeleteHeader("A")
	if len(cfg.GetHeaders()) != 0 {
		t.Fatalf("expected global header deleted")
	}
}

func TestLogLevelParseAndString(t *testing.T) {
	levels := []struct {
		str string
		lvl log.LogLevel
	}{
		{"DEBUG", log.DEBUG},
		{"INFO", log.INFO},
		{"WARN", log.WARN},
		{"ERROR", log.ERROR},
		{"FATAL", log.FATAL},
		{"OTHER", log.INFO},
	}
	for _, tt := range levels {
		if ParseLogLevel(tt.str) != tt.lvl {
			t.Fatalf("ParseLogLevel failed for %s", tt.str)
		}
		if LevelString(tt.lvl) != strings.ToUpper(tt.str) && tt.str != "OTHER" {
			t.Fatalf("LevelString failed for %s", tt.str)
		}
	}
}

func TestAuthIdentityStats(t *testing.T) {
	cfg := &Config{}
	cfg.SetAuth(true, "user", "pass")
	if e, u, p := cfg.GetAuth(); !e || u != "user" || p != "pass" {
		t.Fatalf("unexpected auth: %v %s %s", e, u, p)
	}
	cfg.SetIdentity("name", "id")
	n, id := cfg.GetIdentity()
	if n != "name" || id != "id" {
		t.Fatalf("unexpected identity")
	}
	cfg.SetStatsEnabled(true)
	if !cfg.StatsEnabledState() {
		t.Fatalf("stats not enabled")
	}
}

func TestClientAllowedAndScopedDestinations(t *testing.T) {
	cfg := &Config{}
	if err := cfg.SetPolicyRules("allow all"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetClientRules(
		"allow 10.0.0.0/8 { allow domain example.com; deny all }\ndeny 10.1.2.3\ndefault deny"); err != nil {
		t.Fatal(err)
	}

	if ok, _ := cfg.ClientAllowed("10.5.5.5"); !ok {
		t.Error("10.5.5.5 should be allowed")
	}
	// Longest prefix wins over the broader allow, whatever the written order.
	ok, rule := cfg.ClientAllowed("10.1.2.3")
	if ok {
		t.Error("10.1.2.3 should be denied by the more specific rule")
	}
	if !strings.Contains(rule, "10.1.2.3") {
		t.Errorf("refusal should name the rule, got %q", rule)
	}
	if ok, rule := cfg.ClientAllowed("203.0.113.1"); ok || rule != "default deny" {
		t.Errorf("unlisted client: ok=%v rule=%q", ok, rule)
	}

	// A client with its own destination list uses it; others get the global one.
	if got, _ := cfg.DestinationRulesFor("10.5.5.5").Match("elsewhere.test", nil); got != policy.Deny {
		t.Errorf("scoped client: got %v, want Deny", got)
	}
	if got, _ := cfg.DestinationRulesFor("192.168.1.1").Match("elsewhere.test", nil); got != policy.Allow {
		t.Errorf("unscoped client: got %v, want the global Allow", got)
	}
}

func TestNoClientRulesAdmitsEveryone(t *testing.T) {
	cfg := &Config{}
	if ok, _ := cfg.ClientAllowed("203.0.113.1"); !ok {
		t.Error("with no client table configured, every client may connect")
	}
}

// The prebuilt rule sets have to be rebuilt by every path that can change what
// feeds them. A stale set is worse than a slow one: the UI would report a change
// that never took effect.
func TestHeaderRulesRebuildOnEveryMutation(t *testing.T) {
	cfg := &Config{}

	assertRule := func(what, name, want string) {
		t.Helper()
		h := http.Header{}
		cfg.HeaderRules("10.1.2.3").Apply(h, header.Request, "example.com", nil)
		if got := h.Get(name); got != want {
			t.Errorf("after %s: %s = %q, want %q", what, name, got, want)
		}
	}

	cfg.SetHeader("X-A", "1")
	assertRule("SetHeader", "X-A", "1")

	cfg.SetClientHeader("10.1.2.3", "X-Client", "c")
	assertRule("SetClientHeader", "X-Client", "c")

	if err := cfg.SetHeaderRules("set X-Rule: r"); err != nil {
		t.Fatal(err)
	}
	assertRule("SetHeaderRules", "X-Rule", "r")

	cfg.DeleteClientHeader("10.1.2.3", "X-Client")
	assertRule("DeleteClientHeader", "X-Client", "")

	cfg.DeleteHeader("X-A")
	assertRule("DeleteHeader", "X-A", "")

	cfg.ReplaceHeaders(map[string]string{"X-New": "n"})
	assertRule("ReplaceHeaders", "X-New", "n")
	assertRule("ReplaceHeaders", "X-Rule", "r") // conditional rules survive
}

// A client with no headers of its own reads the global set rather than a nil
// one — the failure that would make every rule inert for most traffic.
func TestHeaderRulesForAnUnknownClient(t *testing.T) {
	cfg := &Config{}
	cfg.SetHeader("X-A", "1")
	cfg.SetClientHeader("10.0.0.1", "X-Only-Theirs", "x")

	h := http.Header{}
	cfg.HeaderRules("203.0.113.9").Apply(h, header.Request, "example.com", nil)
	if h.Get("X-A") != "1" {
		t.Error("an unknown client did not get the global rules")
	}
	if h.Get("X-Only-Theirs") != "" {
		t.Error("an unknown client got another client's header")
	}
}
