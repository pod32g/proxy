package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// PROXY-102. -print-config emits a config file rather than a report, so the
// answer to "what is this process actually running?" can be diffed against
// what is on disk — and fed back in. This pins that: the output parses, and
// running from it produces the same output again.
//
// A fixed point is the strong form. A report that merely looks right can drift
// from the thing it describes; one that reproduces itself cannot have lost a
// setting on the way through.
func TestPrintConfigRoundTrips(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "proxy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	first := filepath.Join(dir, "first.yaml")
	if err := os.WriteFile(first, []byte(`
http: ":0"
allow_private: true
proxy_name: edge-1
policy: |
  deny domain evil.example.com
  allow all
quotas: |
  client requests 50/s burst 100
cache:
  size: 128MB
tunnels:
  max_per_client: 50
upstream_http2: h2c
`), 0o600); err != nil {
		t.Fatal(err)
	}

	print := func(cfg string) string {
		out, err := exec.Command(bin, "-config", cfg, "-db", filepath.Join(dir, "c.db"), "-print-config").Output()
		if err != nil {
			t.Fatalf("-print-config on %s: %v", cfg, err)
		}
		var kept []string
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.HasPrefix(line, "#") {
				kept = append(kept, line)
			}
		}
		return strings.Join(kept, "\n")
	}

	rendered := print(first)
	for _, want := range []string{"proxy_name: edge-1", "upstream_http2: h2c",
		"size: 128MB", "max_per_client: 50", "deny domain evil.example.com"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the effective configuration does not mention %q:\n%s", want, rendered)
		}
	}

	second := filepath.Join(dir, "second.yaml")
	if err := os.WriteFile(second, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	// It has to be accepted...
	if out, err := exec.Command(bin, "-config", second, "-db", filepath.Join(dir, "v.db"), "-validate").CombinedOutput(); err != nil {
		t.Fatalf("the printed configuration was not valid input:\n%s", out)
	}
	// ...and be a fixed point.
	if again := print(second); again != rendered {
		t.Errorf("printing is not stable; a setting was lost or added on the way through:\n--- first\n%s\n--- second\n%s",
			rendered, again)
	}
}

// -validate must not create the database it was told about: a read-only check
// with a side effect is not a check.
func TestValidateTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "proxy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfg := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(cfg, []byte("http: \":0\"\nallow_private: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "should-not-exist.db")
	if out, err := exec.Command(bin, "-config", cfg, "-db", db, "-validate").CombinedOutput(); err != nil {
		t.Fatalf("-validate: %v\n%s", err, out)
	}
	if _, err := os.Stat(db); err == nil {
		t.Error("-validate created the database it was pointed at")
	}
}

// And an invalid file is a non-zero exit, which is what a deployment pipeline
// keys off.
func TestValidateFailsOnABadFile(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "proxy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfg := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfg, []byte("policy: |\n  allow bogus x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-config", cfg, "-db", filepath.Join(dir, "c.db"), "-validate").CombinedOutput()
	if err == nil {
		t.Fatal("-validate accepted an unparseable rule set")
	}
	if !strings.Contains(string(out), "bogus") {
		t.Errorf("the error does not name the bad rule:\n%s", out)
	}
}
