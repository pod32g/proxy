package config

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func loadForReload(t *testing.T, body string) *File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// reloadRace flips between two files continuously while check runs, and reports
// how many checks saw something neither file describes.
func reloadRace(t *testing.T, cfg *Config, a, b *File, check func() bool) (checks, bad int64) {
	t.Helper()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			default:
			}
			f := a
			if n%2 == 1 {
				f = b
			}
			if _, err := f.ApplyTo(cfg); err != nil {
				t.Errorf("ApplyTo: %v", err)
				return
			}
		}
	}()
	var c, x atomic.Int64
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.Add(1)
		if !check() {
			x.Add(1)
		}
	}
	close(stop)
	wg.Wait()
	return c.Load(), x.Load()
}

// PROXY-98. The policy and the client table are composed on the read path, so
// a rule moved from one to the other exists in neither between two setter
// calls. Measured at 43% of evaluations during a continuous reload, on the
// most ordinary edit that touches both: scoping a global deny to one network.
func TestAReloadNeverOpensADeniedDestination(t *testing.T) {
	before := loadForReload(t, `
policy: |
  deny domain evil.example.com
  allow all
clients: |
  allow 127.0.0.0/8
`)
	after := loadForReload(t, `
policy: |
  allow all
clients: |
  allow 127.0.0.0/8 { deny domain evil.example.com; allow all }
`)

	cfg := &Config{}
	if _, err := before.ApplyTo(cfg); err != nil {
		t.Fatal(err)
	}
	checks, allowed := reloadRace(t, cfg, after, before, func() bool {
		return !cfg.EvaluatePolicy("127.0.0.1", "evil.example.com", "").Allowed
	})
	t.Logf("%d evaluations during continuous reload, %d allowed", checks, allowed)
	if checks == 0 {
		t.Fatal("no evaluations ran")
	}
	if allowed > 0 {
		t.Errorf("%d of %d evaluations allowed a destination both configurations deny", allowed, checks)
	}
}

// PROXY-99. A parent and its credentials are one value. Set separately, 48% of
// reads during a rotation saw one parent's address with another's credentials.
func TestAReloadNeverMixesParentsAndCredentials(t *testing.T) {
	a := loadForReload(t, "upstream_proxy:\n  url: http://a.example.com:3128\n  username: ua\n  password: pa\n")
	b := loadForReload(t, "upstream_proxy:\n  url: http://b.example.com:3128\n  username: ub\n  password: pb\n")

	cfg := &Config{}
	if _, err := a.ApplyTo(cfg); err != nil {
		t.Fatal(err)
	}
	checks, mixed := reloadRace(t, cfg, b, a, func() bool {
		p := cfg.UpstreamProxy()
		host, user, pass := p.String(), p.Username, p.Password
		return (host == "http://a.example.com:3128" && user == "ua" && pass == "pa") ||
			(host == "http://b.example.com:3128" && user == "ub" && pass == "pb")
	})
	t.Logf("%d reads during continuous rotation, %d mismatched", checks, mixed)
	if checks == 0 {
		t.Fatal("no reads ran")
	}
	if mixed > 0 {
		t.Errorf("%d of %d reads paired one parent's address with another's credentials", mixed, checks)
	}
}

// The same property for the header map and the conditional rules, which are
// merged on the read path exactly as the policy pair is.
func TestAReloadNeverPublishesHalfTheHeaderRules(t *testing.T) {
	a := loadForReload(t, "headers:\n  X-Set: a\nheader_rules: |\n  set X-Rule: a\n")
	b := loadForReload(t, "headers:\n  X-Set: b\nheader_rules: |\n  set X-Rule: b\n")

	cfg := &Config{}
	if _, err := a.ApplyTo(cfg); err != nil {
		t.Fatal(err)
	}
	checks, mixed := reloadRace(t, cfg, b, a, func() bool {
		set := cfg.HeaderRules("127.0.0.1")
		var got string
		for _, r := range set.Rules {
			if r.Name == "X-Set" {
				got = r.Value
			}
		}
		for _, r := range set.Rules {
			if r.Name == "X-Rule" && r.Value != got {
				return false
			}
		}
		return true
	})
	t.Logf("%d header-set reads during continuous reload, %d mismatched", checks, mixed)
	if mixed > 0 {
		t.Errorf("%d of %d reads mixed the header map from one file with the rules from another", mixed, checks)
	}
}

// And a rejected update still changes nothing, which is the property PROXY-90
// established for a reload that cannot be applied.
func TestARejectedUpdateChangesNothing(t *testing.T) {
	cfg := &Config{}
	if err := cfg.SetPolicyRules("allow all"); err != nil {
		t.Fatal(err)
	}
	cfg.SetProxyName("original")

	bad := "not a rule at all"
	changed, err := cfg.Apply(Update{
		ProxyName: strPtr("changed"),
		Policy:    strPtr("deny all"),
		Clients:   &bad,
	})
	if err == nil {
		t.Fatal("an unparseable update was accepted")
	}
	if len(changed) != 0 {
		t.Errorf("a rejected update reported %v applied", changed)
	}
	if got, _ := cfg.GetIdentity(); got != "original" {
		t.Errorf("proxy_name = %q; a rejected update changed it", got)
	}
	if got := cfg.PolicyRulesText(); got != "allow all" {
		t.Errorf("policy = %q; a rejected update changed it", got)
	}
}
