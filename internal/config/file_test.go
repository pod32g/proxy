package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/pod32g/simple-logger"
)

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func mustLoad(t *testing.T, body string) *File {
	t.Helper()
	f, err := LoadFile(writeConfigFile(t, body))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return f
}

func TestLoadFileReadsEverySection(t *testing.T) {
	f := mustLoad(t, `
mode: forward
http: ":8080"
allow_private: true
connect_ports: [443, 8443]
stats: true
proxy_name: edge-1
headers:
  X-Example: "1"
auth:
  enabled: true
  username: admin
  password: hunter2
log:
  level: DEBUG
  format: json
access_log:
  format: combined
tracing:
  endpoint: localhost:4318
  insecure: true
  sample: 0.25
destination_metrics:
  enabled: true
  top: 5
policy: |
  deny domain internal.example.com
  allow all
clients: |
  allow 10.0.0.0/8
quotas: |
  client requests 10/s
`)
	if *f.Mode != "forward" || *f.HTTP != ":8080" || !*f.AllowPrivate {
		t.Errorf("basics: %+v", f)
	}
	if len(f.ConnectPorts) != 2 || f.ConnectPorts[1] != 8443 {
		t.Errorf("connect_ports: %v", f.ConnectPorts)
	}
	if *f.Auth.Username != "admin" || *f.Log.Level != "DEBUG" {
		t.Errorf("nested sections: %+v", f)
	}
	if *f.Tracing.Sample != 0.25 || *f.DestinationMetrics.Top != 5 {
		t.Errorf("numeric sections: %+v", f)
	}
	if !strings.Contains(*f.Policy, "deny domain") {
		t.Errorf("policy: %q", *f.Policy)
	}
}

// "Absent" and "set to the zero value" must be distinguishable, or a file that
// says nothing about authentication silently turns it off.
func TestAbsentIsNotFalse(t *testing.T) {
	f := mustLoad(t, "mode: forward\n")
	if f.Auth != nil {
		t.Error("an absent auth section decoded as present")
	}
	if f.Stats != nil {
		t.Error("absent stats decoded as false rather than unset")
	}

	cfg := &Config{}
	cfg.SetAuthEnabled(true)
	cfg.SetStatsEnabled(true)
	if _, err := f.ApplyTo(cfg); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	if enabled, _, _ := cfg.GetAuth(); !enabled {
		t.Error("a file that says nothing about auth turned it off")
	}
	if !cfg.StatsEnabledState() {
		t.Error("a file that says nothing about stats turned it off")
	}
}

// A misspelled key is a setting that silently does nothing, which is worse than
// a startup error: the operator believes it took effect.
func TestUnknownKeysAreRejected(t *testing.T) {
	_, err := LoadFile(writeConfigFile(t, "allowprivate: true\n"))
	if err == nil {
		t.Fatal("accepted an unknown key")
	}
	if !strings.Contains(err.Error(), "allowprivate") {
		t.Errorf("error does not name the key: %v", err)
	}
}

func TestValidationRejectsBadValues(t *testing.T) {
	for name, body := range map[string]string{
		"mode":          "mode: sideways\n",
		"log level":     "log:\n  level: SHOUT\n",
		"log format":    "log:\n  format: yaml\n",
		"policy":        "policy: |\n  allow subnet 10.0.0.0/8\n",
		"clients":       "clients: |\n  maybe 10.0.0.0/8\n",
		"quotas":        "quotas: |\n  global requests 10MB/s\n",
		"connect port":  "connect_ports: [70000]\n",
		"sample ratio":  "tracing:\n  sample: 5\n",
		"both password": "auth:\n  password: a\n  password_file: /tmp/b\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadFile(writeConfigFile(t, body)); err == nil {
				t.Errorf("accepted %s", body)
			}
		})
	}
}

// The criterion: a reload that fails validation keeps the running configuration
// and says why. Nothing may be half-applied.
func TestFailedLoadChangesNothing(t *testing.T) {
	cfg := &Config{}
	if err := cfg.SetPolicyRules("allow all"); err != nil {
		t.Fatal(err)
	}
	cfg.SetProxyName("original")

	// A file whose first settings are fine and whose policy is not. If anything
	// applied before validating, proxy_name would already have moved.
	_, err := LoadFile(writeConfigFile(t, "proxy_name: replaced\npolicy: |\n  allow bogus x\n"))
	if err == nil {
		t.Fatal("accepted an invalid policy")
	}
	if name, _ := cfg.GetIdentity(); name != "original" {
		t.Errorf("proxy_name = %q; a rejected file changed the running config", name)
	}
	if cfg.PolicyRulesText() != "allow all" {
		t.Errorf("policy = %q; a rejected file changed the running config", cfg.PolicyRulesText())
	}
}

func TestApplyToReportsWhatChanged(t *testing.T) {
	cfg := &Config{}
	cfg.SetLogLevel(ParseLogLevel("INFO"))

	f := mustLoad(t, "log:\n  level: DEBUG\nproxy_name: edge-1\nquotas: |\n  client requests 10/s\n")
	changed, err := f.ApplyTo(cfg)
	if err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	want := map[string]bool{"log.level": true, "proxy_name": true, "quotas": true}
	if len(changed) != len(want) {
		t.Fatalf("changed = %v, want %v", changed, want)
	}
	for _, c := range changed {
		if !want[c] {
			t.Errorf("unexpected change %q", c)
		}
	}
	if cfg.GetLogLevel() != log.DEBUG {
		t.Error("log level not applied")
	}

	// Applying the same file again is a no-op, so a reload of an unchanged file
	// does not claim to have done something.
	again, err := f.ApplyTo(cfg)
	if err != nil {
		t.Fatalf("second ApplyTo: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("re-applying an unchanged file reported %v", again)
	}
}

// A file describes the headers that should exist, not a patch. Merging would
// make a header impossible to remove by editing the file.
func TestHeadersAreReplacedNotMerged(t *testing.T) {
	cfg := &Config{}
	cfg.SetHeader("X-Old", "1")

	f := mustLoad(t, "headers:\n  X-New: \"2\"\n")
	if _, err := f.ApplyTo(cfg); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	h := cfg.GetHeaders()
	if _, still := h["X-Old"]; still {
		t.Error("a header removed from the file survived the reload")
	}
	if h["X-New"] != "2" {
		t.Errorf("headers = %v", h)
	}
}

// The criterion: settings that cannot change live are enumerated, not
// discovered by users finding that an edit did nothing.
func TestRestartRequiredIsReported(t *testing.T) {
	prev := mustLoad(t, "http: \":8080\"\nmode: forward\nallow_private: false\n")
	next := mustLoad(t, "http: \":9090\"\nmode: reverse\nallow_private: true\n")

	changes := next.RestartRequired(prev)
	byName := map[string]Change{}
	for _, c := range changes {
		byName[c.Setting] = c
	}
	for _, want := range []string{"http", "mode", "allow_private"} {
		c, ok := byName[want]
		if !ok {
			t.Errorf("%s not reported as needing a restart: %v", want, changes)
			continue
		}
		if c.From == "" || c.To == "" {
			t.Errorf("%s reported without both values: %+v", want, c)
		}
	}
	if c := byName["http"]; c.From != ":8080" || c.To != ":9090" {
		t.Errorf("http: %+v", c)
	}
}

func TestRestartRequiredIsSilentWhenNothingMoved(t *testing.T) {
	body := "http: \":8080\"\nmode: forward\nlog:\n  level: INFO\n  format: json\n"
	prev := mustLoad(t, body)
	next := mustLoad(t, body)
	if changes := next.RestartRequired(prev); len(changes) != 0 {
		t.Errorf("an unchanged file reported %v", changes)
	}
}

// Every setting the docs call restart-only must be one RestartRequired can
// actually detect, or the list is a promise the code does not keep.
func TestRestartOnlyListIsHonest(t *testing.T) {
	// Live settings must not appear in the restart-only list.
	live := []string{"policy", "clients", "quotas", "stats", "proxy_name", "proxy_id", "headers", "log.level"}
	for _, name := range live {
		for _, restart := range RestartOnly {
			if name == restart {
				t.Errorf("%q is applied live but listed as restart-only", name)
			}
		}
	}
	if len(RestartOnly) == 0 {
		t.Error("the restart-only list is empty; the docs would promise nothing")
	}
}

func TestPasswordFromFile(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "pass")
	if err := os.WriteFile(secretPath, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := mustLoad(t, "auth:\n  enabled: true\n  username: admin\n  password_file: "+secretPath+"\n")

	cfg := &Config{}
	if _, err := f.ApplyTo(cfg); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	enabled, user, pass := cfg.GetAuth()
	if !enabled || user != "admin" || pass != "from-a-file" {
		t.Errorf("got enabled=%v user=%q pass=%q", enabled, user, pass)
	}
}

// A password file that cannot be read must be an error, not an empty password —
// with auth enabled, an empty credential is the fail-open case.
func TestUnreadablePasswordFileIsAnError(t *testing.T) {
	f := mustLoad(t, "auth:\n  password_file: /nonexistent/proxy-password\n")
	if _, err := f.ApplyTo(&Config{}); err == nil {
		t.Fatal("a missing password file was accepted")
	}
}

func TestNilFileIsHarmless(t *testing.T) {
	var f *File
	changed, err := f.ApplyTo(&Config{})
	if err != nil || changed != nil {
		t.Errorf("got %v, %v", changed, err)
	}
	if c := f.RestartRequired(nil); c != nil {
		t.Errorf("got %v", c)
	}
}
