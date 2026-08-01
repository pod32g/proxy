package config

import (
	"strings"
	"testing"
)

func globalConfig(t *testing.T) *Config {
	t.Helper()
	cfg := &Config{Mode: "forward", TargetURL: "http://global.test"}
	if err := cfg.SetPolicyRules("allow domain global.example\ndeny all"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetClientRules("allow 10.0.0.0/8\ndefault deny"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetQuotas("client requests 100/s"); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// A listener that overrides nothing must behave exactly as the global
// configuration does. Anything else would make adding a second listener change
// the first one's behaviour.
func TestListenerWithoutOverridesFollowsTheGlobalConfig(t *testing.T) {
	cfg := globalConfig(t)
	l := NewListener("internal", "127.0.0.1:1", cfg)

	if got := l.ResolvedMode(); got != "forward" {
		t.Errorf("mode = %q, want the global forward", got)
	}
	if got := l.ResolvedTarget(); got != "http://global.test" {
		t.Errorf("target = %q, want the global one", got)
	}
	if ok, _ := l.ClientAllowed("10.1.2.3"); !ok {
		t.Error("a client the global table allows was refused")
	}
	if ok, _ := l.ClientAllowed("203.0.113.1"); ok {
		t.Error("a client the global table denies was allowed")
	}
	if got := l.QuotaSet().For("10.1.2.3").Requests.PerSecond; got != 100 {
		t.Errorf("quota = %v/s, want the global 100/s", got)
	}
	set := l.DestinationRulesFor("10.1.2.3")
	if set == nil || !strings.Contains(set.String(), "global.example") {
		t.Errorf("destination rules = %v, want the global set", set)
	}
}

func TestListenerOverridesApplyOnlyToIt(t *testing.T) {
	cfg := globalConfig(t)
	l := NewListener("internal", "127.0.0.1:1", cfg)
	if err := l.SetPolicyRules("allow domain internal.example\ndeny all"); err != nil {
		t.Fatal(err)
	}
	if err := l.SetQuotas("client requests 5/s"); err != nil {
		t.Fatal(err)
	}

	if got := l.DestinationRulesFor("10.1.2.3").String(); !strings.Contains(got, "internal.example") {
		t.Errorf("listener rules = %q, want its own", got)
	}
	if got := l.QuotaSet().For("10.1.2.3").Requests.PerSecond; got != 5 {
		t.Errorf("listener quota = %v/s, want its own 5/s", got)
	}

	// The global config must be untouched: another listener still sees it.
	if got := cfg.DestinationRulesFor("10.1.2.3").String(); !strings.Contains(got, "global.example") {
		t.Errorf("global rules = %q; a listener override leaked into them", got)
	}
	if got := cfg.QuotaSet().For("10.1.2.3").Requests.PerSecond; got != 100 {
		t.Errorf("global quota = %v/s; a listener override leaked into it", got)
	}
}

// Overriding one rule set must not silently drop the others. A listener that
// sets only destinations still has to honour the global client table, or adding
// a destination rule quietly opens the listener to everyone.
func TestPartialOverridesKeepTheRest(t *testing.T) {
	cfg := globalConfig(t)
	l := NewListener("internal", "127.0.0.1:1", cfg)
	if err := l.SetPolicyRules("allow all"); err != nil {
		t.Fatal(err)
	}

	if ok, _ := l.ClientAllowed("203.0.113.1"); ok {
		t.Error("overriding destinations dropped the global client table")
	}
	if got := l.QuotaSet().For("10.1.2.3").Requests.PerSecond; got != 100 {
		t.Errorf("quota = %v/s; overriding destinations dropped the global quotas", got)
	}
}

func TestListenerClientOverride(t *testing.T) {
	cfg := globalConfig(t)
	l := NewListener("external", "127.0.0.1:1", cfg)
	if err := l.SetClientRules("allow 203.0.113.0/24\ndefault deny"); err != nil {
		t.Fatal(err)
	}

	if ok, _ := l.ClientAllowed("203.0.113.1"); !ok {
		t.Error("the listener's own client table was not used")
	}
	// And the global table no longer governs this listener.
	if ok, _ := l.ClientAllowed("10.1.2.3"); ok {
		t.Error("the global client table still applied after an override")
	}
	// While the global config is unchanged.
	if ok, _ := cfg.ClientAllowed("10.1.2.3"); !ok {
		t.Error("a listener override leaked into the global client table")
	}
}

func TestOverrideFlags(t *testing.T) {
	cfg := globalConfig(t)
	l := NewListener("a", "127.0.0.1:1", cfg)
	if l.HasPolicyOverride() || l.HasQuotaOverride() {
		t.Error("a fresh listener reports overrides it does not have")
	}
	if err := l.SetQuotas("client requests 5/s"); err != nil {
		t.Fatal(err)
	}
	if !l.HasQuotaOverride() {
		t.Error("a quota override was not reported")
	}
	if l.HasPolicyOverride() {
		t.Error("setting quotas reported a policy override")
	}
}

func TestBuildListenersFromFile(t *testing.T) {
	cfg := globalConfig(t)
	f := mustLoad(t, `
listeners:
  - name: internal
    address: "127.0.0.1:8081"
    allow_private: true
    connect_ports: [443, 8443]
    policy: |
      allow all
  - name: external
    address: "127.0.0.1:8082"
    mode: reverse
    target: http://backend:9000
`)
	built, err := f.BuildListeners(cfg, false, []int{443})
	if err != nil {
		t.Fatalf("BuildListeners: %v", err)
	}
	if len(built) != 2 {
		t.Fatalf("got %d listeners, want 2", len(built))
	}

	internal := built[0]
	if internal.Name != "internal" || internal.Addr != "127.0.0.1:8081" {
		t.Errorf("got %+v", internal)
	}
	if !internal.AllowPrivate {
		t.Error("allow_private override not applied")
	}
	if len(internal.ConnectPorts) != 2 {
		t.Errorf("connect_ports = %v", internal.ConnectPorts)
	}
	if !internal.HasPolicyOverride() {
		t.Error("policy override not applied")
	}

	external := built[1]
	if external.ResolvedMode() != "reverse" || external.ResolvedTarget() != "http://backend:9000" {
		t.Errorf("got mode=%q target=%q", external.ResolvedMode(), external.ResolvedTarget())
	}
	// It inherits the defaults it did not name.
	if external.AllowPrivate {
		t.Error("allow_private should have come from the default")
	}
	if external.HasPolicyOverride() {
		t.Error("external should follow the global policy")
	}
}

func TestListenerFileValidation(t *testing.T) {
	for name, body := range map[string]string{
		"no name":        "listeners:\n  - address: \"127.0.0.1:1\"\n",
		"no address":     "listeners:\n  - name: a\n",
		"half TLS":       "listeners:\n  - name: a\n    address: \"127.0.0.1:1\"\n    cert: c\n",
		"bad mode":       "listeners:\n  - name: a\n    address: \"127.0.0.1:1\"\n    mode: sideways\n",
		"no target":      "listeners:\n  - name: a\n    address: \"127.0.0.1:1\"\n    mode: reverse\n",
		"bad port":       "listeners:\n  - name: a\n    address: \"127.0.0.1:1\"\n    connect_ports: [0]\n",
		"bad policy":     "listeners:\n  - name: a\n    address: \"127.0.0.1:1\"\n    policy: |\n      allow bogus x\n",
		"bad quotas":     "listeners:\n  - name: a\n    address: \"127.0.0.1:1\"\n    quotas: |\n      global requests 10MB/s\n",
		"duplicate name": "listeners:\n  - name: a\n    address: \"127.0.0.1:1\"\n  - name: a\n    address: \"127.0.0.1:2\"\n",
		"reserved name":  "listeners:\n  - name: admin\n    address: \"127.0.0.1:1\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadFile(writeConfigFile(t, body)); err == nil {
				t.Error("accepted an invalid listener")
			}
		})
	}
}

// A listener name lands in a metrics label and a log field. Two listeners
// sharing one merges their traffic into a single series under a name that no
// longer identifies anything.
func TestDuplicateListenerNameIsRejected(t *testing.T) {
	_, err := LoadFile(writeConfigFile(t,
		"listeners:\n  - name: edge\n    address: \"127.0.0.1:1\"\n  - name: edge\n    address: \"127.0.0.1:2\"\n"))
	if err == nil {
		t.Fatal("accepted a duplicate listener name")
	}
	if !strings.Contains(err.Error(), "edge") {
		t.Errorf("error does not name the collision: %v", err)
	}
}
