package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func auditStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// settingsOf indexes entries by setting, for assertions that do not care about
// the order of unrelated changes.
func settingsOf(entries []AuditEntry) map[string]AuditEntry {
	out := make(map[string]AuditEntry, len(entries))
	for _, e := range entries {
		if _, seen := out[e.Setting]; !seen {
			out[e.Setting] = e
		}
	}
	return out
}

func TestAuditRecordsWhatChanged(t *testing.T) {
	store := auditStore(t)
	cfg := &Config{}
	cfg.SetLogLevel(ParseLogLevel("INFO"))
	if err := store.Save(cfg, Actor{Via: ViaStartup}); err != nil {
		t.Fatalf("first save: %v", err)
	}

	cfg.SetLogLevel(ParseLogLevel("DEBUG"))
	cfg.SetProxyName("edge-1")
	if err := store.Save(cfg, Actor{Source: "10.1.2.3", User: "admin", Via: ViaUI}); err != nil {
		t.Fatalf("second save: %v", err)
	}

	entries, err := store.Audit(50)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	by := settingsOf(entries)

	level, ok := by["log_level"]
	if !ok {
		t.Fatalf("log_level change not recorded: %+v", entries)
	}
	if level.OldValue != "INFO" || level.NewValue != "DEBUG" {
		t.Errorf("log_level: %q -> %q, want INFO -> DEBUG", level.OldValue, level.NewValue)
	}
	if level.User != "admin" || level.Source != "10.1.2.3" || level.Via != ViaUI {
		t.Errorf("actor not recorded: %+v", level)
	}
	if level.At.IsZero() {
		t.Error("timestamp not recorded")
	}
	if name := by["proxy_name"]; name.NewValue != "edge-1" {
		t.Errorf("proxy_name: %+v", name)
	}
}

// Newest first, because an investigation starts from "what happened most
// recently" and paging backwards through history to find it is the wrong shape.
func TestAuditIsNewestFirst(t *testing.T) {
	store := auditStore(t)
	cfg := &Config{}
	for _, name := range []string{"a", "b", "c"} {
		cfg.SetProxyName(name)
		if err := store.Save(cfg, Actor{}); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}
	entries, err := store.Audit(10)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("got %d entries, want at least 3", len(entries))
	}
	if entries[0].NewValue != "c" {
		t.Errorf("first entry is %q, want the most recent change", entries[0].NewValue)
	}
}

// A save that changes nothing must record nothing. An audit full of no-op rows
// is one nobody reads, which is the same as not having one.
func TestUnchangedSaveRecordsNothing(t *testing.T) {
	store := auditStore(t)
	cfg := &Config{}
	cfg.SetProxyName("edge-1")
	if err := store.Save(cfg, Actor{}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	before, _ := store.Audit(100)

	for i := 0; i < 5; i++ {
		if err := store.Save(cfg, Actor{}); err != nil {
			t.Fatalf("repeat save: %v", err)
		}
	}
	after, _ := store.Audit(100)
	if len(after) != len(before) {
		t.Errorf("five identical saves added %d entries", len(after)-len(before))
	}
}

// The criterion, asserted directly: a known password must not appear anywhere
// in the audit table, in any column.
func TestPasswordNeverReachesTheAuditTable(t *testing.T) {
	const secret = "hunter2-do-not-log-me"
	const username = "svc-account-name"

	for _, encrypted := range []bool{false, true} {
		name := "plaintext store"
		if encrypted {
			name = "encrypted store"
		}
		t.Run(name, func(t *testing.T) {
			store := auditStore(t)
			cfg := &Config{}
			if encrypted {
				cfg.SecretKey = "an-encryption-secret"
			}
			cfg.SetCredentials("initial", "initial-pass")
			if err := store.Save(cfg, Actor{}); err != nil {
				t.Fatalf("first save: %v", err)
			}
			cfg.SetCredentials(username, secret)
			if err := store.Save(cfg, Actor{User: "admin", Via: ViaAPI}); err != nil {
				t.Fatalf("second save: %v", err)
			}

			// Scan the raw table, not the accessor: a leak through a column the
			// reader happens not to select would still be a leak on disk.
			rows, err := store.db.Query(
				`SELECT ts, source, actor, via, setting, old_value, new_value FROM audit`)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			defer rows.Close()
			var found bool
			for rows.Next() {
				var cells [7]any
				var vals [7]string
				for i := range cells {
					cells[i] = &vals[i]
				}
				if err := rows.Scan(cells[:]...); err != nil {
					t.Fatalf("scan: %v", err)
				}
				joined := strings.Join(vals[:], "\x00")
				if strings.Contains(joined, secret) {
					t.Errorf("password found in the audit table: %q", joined)
				}
				if strings.Contains(joined, username) {
					t.Errorf("username found in the audit table: %q", joined)
				}
				if vals[4] == "password" {
					found = true
					if vals[6] != auditSet {
						t.Errorf("password new value = %q, want %q", vals[6], auditSet)
					}
				}
			}
			if !found {
				t.Error("password change was not recorded at all; it must be recorded, just not with the value")
			}
		})
	}
}

// The trap this design has to avoid: sealing uses a fresh nonce, so the stored
// ciphertext differs on every save even when the password is untouched. Diffing
// stored forms would record a credential change on every single write, and an
// audit that cries wolf trains its reader to ignore the entry that matters.
func TestEncryptedCredentialsAreDiffedOnPlaintext(t *testing.T) {
	store := auditStore(t)
	cfg := &Config{SecretKey: "an-encryption-secret"}
	cfg.SetCredentials("admin", "unchanging")
	if err := store.Save(cfg, Actor{}); err != nil {
		t.Fatalf("first save: %v", err)
	}

	// Change something else entirely, several times.
	for _, name := range []string{"a", "b", "c"} {
		cfg.SetProxyName(name)
		if err := store.Save(cfg, Actor{}); err != nil {
			t.Fatalf("save: %v", err)
		}
	}

	entries, err := store.Audit(100)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	var credentialRows int
	for _, e := range entries {
		if redactedSettings[e.Setting] {
			credentialRows++
		}
	}
	// One each for username and password, from the first save. Not four.
	if credentialRows != 2 {
		t.Errorf("got %d credential entries after three unrelated saves, want 2 (%+v)",
			credentialRows, entries)
	}
}

// Unset to set is a real transition an investigation wants, and neither word is
// a secret.
func TestCredentialTransitionsAreVisible(t *testing.T) {
	store := auditStore(t)
	cfg := &Config{}
	if err := store.Save(cfg, Actor{}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	cfg.SetCredentials("admin", "a-password")
	if err := store.Save(cfg, Actor{}); err != nil {
		t.Fatalf("second save: %v", err)
	}

	entries, _ := store.Audit(100)
	by := settingsOf(entries)
	pass, ok := by["password"]
	if !ok {
		t.Fatal("password change not recorded")
	}
	if pass.OldValue != auditUnset || pass.NewValue != auditSet {
		t.Errorf("password: %q -> %q, want %q -> %q",
			pass.OldValue, pass.NewValue, auditUnset, auditSet)
	}
}

// Growth is bounded by row count, trimmed in the same transaction, so there is
// no external job to forget to schedule.
func TestAuditGrowthIsBounded(t *testing.T) {
	store := auditStore(t)
	cfg := &Config{}
	// Comfortably past the retention limit.
	for i := 0; i < AuditRetention+250; i++ {
		cfg.SetProxyName(strings.Repeat("x", i%40+1))
		if err := store.Save(cfg, Actor{}); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count > AuditRetention {
		t.Errorf("audit table holds %d rows, want at most %d", count, AuditRetention)
	}
	// And the survivors are the recent ones, not an arbitrary window.
	entries, _ := store.Audit(1)
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	if want := strings.Repeat("x", (AuditRetention+249)%40+1); entries[0].NewValue != want {
		t.Errorf("newest entry is %q, want the last change %q", entries[0].NewValue, want)
	}
}

// Policy, client rules and quotas are configuration an operator can change from
// the admin surface, so they belong in the trail alongside the credentials.
func TestPolicyAndQuotaChangesAreAudited(t *testing.T) {
	store := auditStore(t)
	cfg := &Config{}
	if err := store.Save(cfg, Actor{}); err != nil {
		t.Fatalf("first save: %v", err)
	}

	if err := cfg.SetPolicyRules("deny all"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetClientRules("deny 10.1.2.3"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetQuotas("client requests 10/s"); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(cfg, Actor{User: "admin", Via: ViaAPI}); err != nil {
		t.Fatalf("second save: %v", err)
	}

	by := settingsOf(mustAudit(t, store))
	for setting, want := range map[string]string{
		"policy_rules": "deny all",
		"client_rules": "deny 10.1.2.3",
		"quota_rules":  "client requests 10/s",
	} {
		e, ok := by[setting]
		if !ok {
			t.Errorf("%s change not recorded", setting)
			continue
		}
		if e.NewValue != want {
			t.Errorf("%s new value = %q, want %q", setting, e.NewValue, want)
		}
	}
}

func mustAudit(t *testing.T, store *Store) []AuditEntry {
	t.Helper()
	entries, err := store.Audit(200)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	return entries
}

func TestAuditOnNilStoreIsHarmless(t *testing.T) {
	var s *Store
	entries, err := s.Audit(10)
	if err != nil || entries != nil {
		t.Errorf("got %v, %v; want nil, nil", entries, err)
	}
}

// The trail and the change it describes must commit or roll back together. This
// drives the direction that is easy to get wrong: if the audit write fails, the
// configuration change must not survive either, or the store ends up holding a
// change that nothing recorded.
func TestAuditFailureRollsBackTheChange(t *testing.T) {
	store := auditStore(t)
	cfg := &Config{}
	cfg.SetProxyName("before")
	if err := store.Save(cfg, Actor{}); err != nil {
		t.Fatalf("first save: %v", err)
	}

	// Break the audit table only. The settings write still succeeds; the audit
	// insert cannot.
	if _, err := store.db.Exec(`DROP TABLE audit`); err != nil {
		t.Fatalf("drop audit: %v", err)
	}

	cfg.SetProxyName("after")
	if err := store.Save(cfg, Actor{}); err == nil {
		t.Fatal("Save reported success with the audit table missing")
	}

	// The setting must still read "before": the transaction rolled back.
	var stored string
	if err := store.db.QueryRow(
		`SELECT value FROM settings WHERE key='proxy_name'`).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored != "before" {
		t.Errorf("proxy_name = %q; the change was committed without an audit entry", stored)
	}
}
