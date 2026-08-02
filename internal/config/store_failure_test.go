package config

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// PROXY-94. Every settings read used the error only as a presence check, so
// sql.ErrNoRows and a disk error were the same thing. A database that opened
// but could not be read produced a proxy with no destination policy, no client
// table and no quotas — silently, and fail-open: a client table saying
// "default deny" became one that admits everyone.
func TestAnUnreadableStoreIsAnErrorNotAnEmptyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	seed := &Config{}
	if err := seed.SetPolicyRules("deny domain evil.example.com\nallow all"); err != nil {
		t.Fatal(err)
	}
	if err := seed.SetClientRules("allow 10.0.0.0/8\ndefault deny"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(seed, Actor{Via: ViaStartup}); err != nil {
		t.Fatal(err)
	}

	// Opens, initialises, and cannot be read: a stand-in for a bad block or a
	// page that will not come back.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE settings`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	got := &Config{}
	err = s.Load(got)
	if err == nil {
		t.Fatal("a database that could not be read reported no error")
	}
	if !strings.Contains(err.Error(), "settings") {
		t.Errorf("the error does not say what could not be read: %v", err)
	}
	// The caller refuses to start on this, but the values must not be
	// half-applied either — a partial read is what made it look deliberate.
	if got.PolicyRulesText() != "" || got.ClientRulesText() != "" {
		t.Errorf("a failed load applied some settings: policy=%q clients=%q",
			got.PolicyRulesText(), got.ClientRulesText())
	}
}

// The property in isolation, because the test above passes for the wrong
// reason: dropping the settings table also breaks salt(), which checks its own
// error, so Load reports a failure whether or not the per-setting reads do.
// Written the first way it passed against the unfixed code.
func TestSettingDistinguishesMissingFromUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Present table, absent key: not set, not an error.
	if v, ok, err := s.setting("policy_rules"); err != nil || ok || v != "" {
		t.Errorf("absent setting = (%q, %v, %v), want (\"\", false, nil)", v, ok, err)
	}

	// Present key.
	cfg := &Config{}
	if err := cfg.SetPolicyRules("deny all"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(cfg, Actor{Via: ViaStartup}); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.setting("policy_rules"); err != nil || !ok || v != "deny all" {
		t.Errorf("stored setting = (%q, %v, %v), want (\"deny all\", true, nil)", v, ok, err)
	}

	// Unreadable: an error, not silence. This is the distinction the whole
	// finding turns on — a row that cannot be read used to look like one that
	// was never written.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE settings`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	v, ok, err := s.setting("policy_rules")
	if err == nil {
		t.Fatalf("an unreadable setting returned (%q, %v, nil) — indistinguishable from absent", v, ok)
	}
	if !strings.Contains(err.Error(), "policy_rules") {
		t.Errorf("the error does not name the setting: %v", err)
	}
}

// A fresh database has no rows, and that is not a failure.
func TestAnEmptyStoreLoadsCleanly(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &Config{}
	if err := s.Load(cfg); err != nil {
		t.Fatalf("an empty store failed to load: %v", err)
	}
	if cfg.PolicyRulesText() != "" {
		t.Errorf("an empty store produced a policy: %q", cfg.PolicyRulesText())
	}
}

// And a round trip still works, so the new reader did not break reading.
func TestStoreRoundTripsEverySetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	in := &Config{SecretKey: "sekrit"}
	in.SetProxyName("edge-1")
	in.SetProxyID("abc")
	in.SetStatsEnabled(true)
	in.SetCredentials("admin", "pw")
	if err := in.SetPolicyRules("deny all"); err != nil {
		t.Fatal(err)
	}
	if err := in.SetClientRules("allow 10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if err := in.SetQuotas("client requests 50/s"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(in, Actor{Via: ViaStartup}); err != nil {
		t.Fatal(err)
	}

	out := &Config{SecretKey: "sekrit"}
	if err := s.Load(out); err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"policy", out.PolicyRulesText(), "deny all"},
		{"clients", out.ClientRulesText(), "allow 10.0.0.0/8"},
		{"quotas", out.QuotaText(), "client requests 50/s"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if name, id := out.GetIdentity(); name != "edge-1" || id != "abc" {
		t.Errorf("identity = %q/%q", name, id)
	}
	if _, u, p := out.GetAuth(); u != "admin" || p != "pw" {
		t.Errorf("credentials = %q/%q", u, p)
	}
	if !out.StatsEnabledState() {
		t.Error("stats did not round-trip")
	}
}
