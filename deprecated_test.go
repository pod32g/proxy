package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pod32g/proxy/internal/config"
)

// A flag cannot be deprecated in favour of somewhere it cannot go, and a stale
// entry naming a flag that no longer exists is a warning nobody will ever see.
func TestTheDeprecationListIsHonest(t *testing.T) {
	flags := declaredFlags(t)
	file := fileSettings(t)

	for name, d := range deprecated {
		if !contains(flags, name) {
			t.Errorf("deprecated lists -%s, which is not a flag any more", name)
			continue
		}
		if d.instead == "" {
			t.Errorf("-%s is deprecated with nothing to use instead", name)
		}
		// The replacement is named in config-file terms, so the setting it
		// points at has to exist.
		key := strings.TrimSuffix(strings.Fields(d.instead)[0], ":")
		if !file[key] {
			t.Errorf("-%s says to use %q, but %q is not a config-file setting",
				name, d.instead, key)
		}
		if env := envNameFor(name); env != "" && !strings.HasPrefix(env, "PROXY_") {
			t.Errorf("-%s maps to environment variable %q, which is not one of ours", name, env)
		}
	}
}

// PROXY-101. The four rule settings were assembled by four near-identical
// blocks. One helper now does it, and this pins the precedence it states:
// inline rules first, then the file's, applied as one ordered list.
func TestRuleSettingsMergeInlineThenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(path, []byte("deny domain fromfile.example.com\nallow all\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	inline := policyFlags{"deny domain inline.example.com"}
	explicit := map[string]bool{}
	if err := applyRuleSettings(cfg, explicit, []ruleSetting{
		{"policy-rule", &inline, &path, "-policy-file", cfg.SetPolicyRules},
	}); err != nil {
		t.Fatalf("applyRuleSettings: %v", err)
	}

	got := cfg.PolicyRulesText()
	inlineAt := strings.Index(got, "inline.example.com")
	fileAt := strings.Index(got, "fromfile.example.com")
	if inlineAt < 0 || fileAt < 0 {
		t.Fatalf("both sources should contribute; got:\n%s", got)
	}
	if inlineAt > fileAt {
		t.Errorf("the file's rules came before the inline ones; ordering is the semantics:\n%s", got)
	}
	if !explicit["policy-rule"] {
		t.Error("the setting was not recorded as explicitly set, so the config file would overwrite it")
	}

	// Both denies are in force, which is the point of merging rather than
	// letting one route win outright.
	for _, host := range []string{"inline.example.com", "fromfile.example.com"} {
		if cfg.EvaluatePolicy("10.0.0.1", host, "").Allowed {
			t.Errorf("%s was allowed; the merged list should deny it", host)
		}
	}
}

// A setting with no file route is not a special case in the helper.
func TestARuleSettingWithNoFileRouteStillApplies(t *testing.T) {
	cfg := &config.Config{}
	inline := policyFlags{"set X-A: 1"}
	explicit := map[string]bool{}
	if err := applyRuleSettings(cfg, explicit, []ruleSetting{
		{"header-rule", &inline, nil, "", cfg.SetHeaderRules},
	}); err != nil {
		t.Fatalf("applyRuleSettings: %v", err)
	}
	if cfg.HeaderRulesText() != "set X-A: 1" {
		t.Errorf("header rules = %q", cfg.HeaderRulesText())
	}
	if !explicit["header-rule"] {
		t.Error("the setting was not recorded as explicitly set")
	}
}

// An unreadable file names the flag, rather than failing somewhere generic.
func TestAMissingRuleFileNamesTheFlag(t *testing.T) {
	cfg := &config.Config{}
	var inline policyFlags
	missing := "/nonexistent/rules.txt"
	err := applyRuleSettings(cfg, map[string]bool{}, []ruleSetting{
		{"policy-rule", &inline, &missing, "-policy-file", cfg.SetPolicyRules},
	})
	if err == nil {
		t.Fatal("a missing rule file was accepted")
	}
	if !strings.Contains(err.Error(), "-policy-file") {
		t.Errorf("the error does not name the flag: %v", err)
	}
}
