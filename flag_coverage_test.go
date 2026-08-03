package main

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// bootstrapOnly are the flags that deliberately have no config-file equivalent.
//
// Each names where configuration lives, or runs where no file is available, so
// putting it in the file would be circular or useless. Everything else must be
// expressible in the file — see TestEveryFlagCanBeSetInTheConfigFile.
var bootstrapOnly = map[string]string{
	"config":      "names the file itself",
	"db":          "names the database the file's settings are persisted to",
	"healthcheck": "runs in a container HEALTHCHECK, with no file mounted",
	"help":        "not a setting",
}

// aliases maps a flag to the yaml path that expresses it. A flag whose name
// already matches its yaml key, with dashes for underscores, needs no entry.
var aliases = map[string]string{
	"auth":                    "auth.enabled",
	"auth-user":               "auth.username",
	"auth-pass":               "auth.password",
	"auth-pass-file":          "auth.password_file",
	"log-level":               "log.level",
	"log-format":              "log.format",
	"access-log":              "access_log.format",
	"access-log-file":         "access_log.file",
	"otel-endpoint":           "tracing.endpoint",
	"otel-insecure":           "tracing.insecure",
	"otel-sample":             "tracing.sample",
	"destination-metrics":     "destination_metrics.enabled",
	"destination-metrics-top": "destination_metrics.top",
	"admin-http":              "admin.http",
	"admin-cert":              "admin.cert",
	"admin-key":               "admin.key",
	"upstream-ca":             "upstream_tls.ca",
	"upstream-cert":           "upstream_tls.cert",
	"upstream-key":            "upstream_tls.key",
	"upstream-proxy":          "upstream_proxy.url",
	"no-proxy":                "upstream_proxy.no_proxy",
	"cache":                   "cache.size",
	"cache-max-entry":         "cache.max_entry",
	"pac":                     "pac.enabled",
	"pac-address":             "pac.address",
	"pac-hint-direct":         "pac.hint_direct",
	"max-tunnels":             "tunnels.max",
	"max-tunnels-per-client":  "tunnels.max_per_client",
	"tunnel-idle-timeout":     "tunnels.idle_timeout",
	// The rule settings arrive by a repeatable flag and a file of the same
	// rules; both feed one yaml key. See PROXY-101.
	"policy-rule":    "policy",
	"policy-file":    "policy",
	"client-rule":    "clients",
	"client-file":    "clients",
	"quota-rule":     "quotas",
	"quota-file":     "quotas",
	"header-rule":    "header_rules",
	"header":         "headers",
	"secret":         "secret",
	"secret-file":    "secret_file",
	"health-path":    "health_path",
	"allow-private":  "allow_private",
	"connect-ports":  "connect_ports",
	"metrics-public": "metrics_public",
	"proxy-name":     "proxy_name",
	"proxy-id":       "proxy_id",
	"upstream-http2": "upstream_http2",
}

// PROXY-100. The config file was not a superset of the flags, and nothing said
// so: nine settings — the response cache, the HTTP/2 mode, the PAC file and the
// three tunnel limits — could only be reached by flag or environment, so a
// deployment keeping its configuration in proxy.yaml could not turn the cache
// on or bound how many tunnels a client holds.
//
// PROXY-77's walk asserts every *file* setting is classified. It runs in one
// direction only, which is why three settings added in later work were wired
// into flags and Policy and never into File. This is the other direction.
func TestEveryFlagCanBeSetInTheConfigFile(t *testing.T) {
	flags := declaredFlags(t)
	if len(flags) < 40 {
		t.Fatalf("found only %d flags; the parse is wrong, not the code", len(flags))
	}
	file := fileSettings(t)

	var missing []string
	for _, f := range flags {
		if _, ok := bootstrapOnly[f]; ok {
			continue
		}
		key := aliases[f]
		if key == "" {
			key = strings.ReplaceAll(f, "-", "_")
		}
		if !file[key] {
			missing = append(missing, f+" (looked for "+key+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("-%s has no config-file equivalent: a deployment configured by "+
			"file cannot reach it. Add a yaml key, or add it to bootstrapOnly with "+
			"a reason.", m)
	}

	// And the reverse for the alias table itself, so a renamed flag does not
	// leave a stale entry quietly matching nothing.
	for f := range aliases {
		if !contains(flags, f) {
			t.Errorf("aliases has %q, which is not a flag any more", f)
		}
	}
	for f := range bootstrapOnly {
		if f != "help" && !contains(flags, f) {
			t.Errorf("bootstrapOnly has %q, which is not a flag any more", f)
		}
	}
}

// declaredFlags asks the binary what flags it has, rather than parsing the
// source: -help is the list the operator actually sees, and a flag registered
// somewhere this test did not think to grep still appears in it.
func declaredFlags(t *testing.T) []string {
	t.Helper()
	bin := t.TempDir() + "/proxy"
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, "-help")
	out, _ := cmd.CombinedOutput() // -help exits non-zero
	var flags []string
	for _, m := range regexp.MustCompile(`(?m)^\s+-([a-z0-9-]+)`).FindAllStringSubmatch(string(out), -1) {
		flags = append(flags, m[1])
	}
	sort.Strings(flags)
	return flags
}

// fileSettings returns every yaml path the config file accepts, as
// "block.field" for nested ones.
//
// A nested block's own yaml tag sits on its closing brace, *after* its fields,
// so the fields have to be held until the block names itself. Written the
// obvious way — assume the block name comes first — every nested setting is
// attributed to whatever block preceded it, and the test passes by matching
// nothing.
func fileSettings(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("internal/config/file.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "type File struct {")
	if start < 0 {
		t.Fatal("could not find the File struct")
	}
	end := strings.Index(body[start:], "\n}\n") + start

	tag := regexp.MustCompile(`yaml:"([a-z0-9_]+)`)
	out := map[string]bool{}
	var pending []string
	for _, line := range strings.Split(body[start:end], "\n") {
		m := tag.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1]
		indent := len(line) - len(strings.TrimLeft(line, "\t"))
		if indent > 1 {
			pending = append(pending, key)
			continue
		}
		// A top-level tag. If fields are waiting, this is their block's
		// closing brace naming it; otherwise it is a scalar of its own.
		out[key] = true
		for _, f := range pending {
			out[key+"."+f] = true
		}
		pending = nil
	}
	if len(pending) != 0 {
		t.Fatalf("nested settings with no block: %v", pending)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
