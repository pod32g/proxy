package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/pod32g/simple-logger"
)

func TestEncryptDecrypt(t *testing.T) {
	salt := []byte("0123456789abcdef")
	enc, err := encrypt("key", salt, "data")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, cipherV2Prefix) {
		t.Fatalf("ciphertext not tagged with the current scheme: %q", enc)
	}
	dec, err := decrypt("key", salt, enc)
	if err != nil || dec != "data" {
		t.Fatalf("decrypt mismatch: %v %s", err, dec)
	}
	if _, err := decrypt("wrong", salt, enc); err == nil {
		t.Fatal("expected the wrong secret to fail")
	}
	if _, err := decrypt("key", []byte("different-salt.."), enc); err == nil {
		t.Fatal("expected a different salt to fail")
	}
}

// The salt must be per-database, otherwise two installs sharing a secret share
// a key and a stolen database is precomputable.
func TestSaltIsRandomPerDatabase(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		store := newTestStore(t)
		cfg := &Config{SecretKey: "k"}
		cfg.SetAuth(true, "u", "p")
		if err := store.Save(cfg, Actor{}); err != nil {
			t.Fatal(err)
		}
		salt, err := store.salt()
		if err != nil || len(salt) != kdfSaltLn {
			t.Fatalf("bad salt: %v %v", salt, err)
		}
		if seen[string(salt)] {
			t.Fatal("salt reused across databases")
		}
		seen[string(salt)] = true
		store.Close()
	}
}

// A database written by the pre-KDF build must still open, and must be
// transparently re-sealed with the current scheme on the next Save.
func TestLegacyCiphertextMigrates(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	legacy, err := seal(deriveKeyLegacy("k"), "old-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(
		`INSERT INTO settings(key, value) VALUES('username','u'),('password',?)`, legacy); err != nil {
		t.Fatal(err)
	}
	// username was stored unencrypted in this fixture; password was not.
	if _, err := store.db.Exec(`UPDATE settings SET value=? WHERE key='username'`,
		mustSeal(t, deriveKeyLegacy("k"), "old-user")); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{SecretKey: "k"}
	if err := store.Load(cfg); err != nil {
		t.Fatal(err)
	}
	if _, u, p := cfg.GetAuth(); u != "old-user" || p != "old-password" {
		t.Fatalf("legacy credentials did not survive load: %q %q", u, p)
	}

	if err := store.Save(cfg, Actor{}); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := store.db.QueryRow(`SELECT value FROM settings WHERE key='password'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, cipherV2Prefix) {
		t.Fatalf("Save did not re-seal legacy ciphertext: %q", stored)
	}

	reloaded := &Config{SecretKey: "k"}
	if err := store.Load(reloaded); err != nil {
		t.Fatal(err)
	}
	if _, u, p := reloaded.GetAuth(); u != "old-user" || p != "old-password" {
		t.Fatalf("re-sealed credentials broken: %q %q", u, p)
	}
}

// A wrong -secret must not silently blank working credentials on load.
func TestWrongSecretKeepsCurrentCredentials(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	saved := &Config{SecretKey: "right"}
	saved.SetAuth(true, "u", "p")
	if err := store.Save(saved, Actor{}); err != nil {
		t.Fatal(err)
	}

	loaded := &Config{SecretKey: "wrong"}
	loaded.SetAuth(true, "flag-user", "flag-pass")
	if err := store.Load(loaded); err != nil {
		t.Fatal(err)
	}
	if _, u, p := loaded.GetAuth(); u != "flag-user" || p != "flag-pass" {
		t.Fatalf("undecryptable credentials clobbered the live ones: %q %q", u, p)
	}
}

func TestCredentialsAtRisk(t *testing.T) {
	cfg := &Config{}
	if CredentialsAtRisk(cfg) {
		t.Fatal("no credentials set, nothing at risk")
	}
	cfg.SetAuth(true, "u", "p")
	if !CredentialsAtRisk(cfg) {
		t.Fatal("plaintext credentials with no secret should be flagged")
	}
	cfg.SecretKey = "k"
	if CredentialsAtRisk(cfg) {
		t.Fatal("encrypted credentials should not be flagged")
	}
}

func mustSeal(t *testing.T, key []byte, plain string) string {
	t.Helper()
	out, err := seal(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStoreSaveLoad(t *testing.T) {
	f, err := os.CreateTemp("", "db-*.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{SecretKey: "k"}
	cfg.SetHeader("H", "v")
	cfg.SetLogLevel(log.DEBUG)
	cfg.SetAuth(true, "u", "p")
	cfg.SetStatsEnabled(true)
	cfg.SetIdentity("n", "id")
	if err := store.Save(cfg, Actor{}); err != nil {
		t.Fatal(err)
	}
	loaded := &Config{SecretKey: "k"}
	if err := store.Load(loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.GetHeaders()["H"] != "v" || loaded.GetLogLevel() != log.DEBUG {
		t.Fatalf("load mismatch")
	}
	e, u, p := loaded.GetAuth()
	if !e || u != "u" || p != "p" {
		t.Fatalf("auth mismatch")
	}
	if !loaded.StatsEnabledState() {
		t.Fatalf("stats mismatch")
	}
	n, id2 := loaded.GetIdentity()
	if n != "n" || id2 != "id" {
		t.Fatalf("id mismatch")
	}
	store.Close()
}

// Save runs on the request path, so it must not re-derive the scrypt key each
// time. The parameters are deliberately expensive; the key is not.
func TestSaveDoesNotRederiveKey(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cfg := &Config{SecretKey: "s3kr1t"}
	cfg.SetAuth(true, "alice", "s3cret")
	if err := store.Save(cfg, Actor{}); err != nil { // warm: pays for the derivation once
		t.Fatal(err)
	}

	start := time.Now()
	for i := 0; i < 20; i++ {
		if err := store.Save(cfg, Actor{}); err != nil {
			t.Fatal(err)
		}
	}
	per := time.Since(start) / 20
	if per > 10*time.Millisecond {
		t.Errorf("Save() costs %v per call; the key is being re-derived", per.Round(time.Millisecond))
	}
}

// A secret that cannot open the stored credentials keeps the live ones — but
// silently doing so leaves the operator with no idea it happened.
func TestWrongSecretWarns(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	saved := &Config{SecretKey: "right"}
	saved.SetAuth(true, "u", "p")
	if err := store.Save(saved, Actor{}); err != nil {
		t.Fatal(err)
	}
	store.Warnings() // drain anything from the save

	loaded := &Config{SecretKey: "wrong"}
	loaded.SetAuth(true, "flag-user", "flag-pass")
	if err := store.Load(loaded); err != nil {
		t.Fatal(err)
	}
	warnings := store.Warnings()
	if len(warnings) == 0 {
		t.Fatal("no warning emitted for undecryptable credentials")
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "username") || !strings.Contains(joined, "password") {
		t.Errorf("warnings do not name the affected settings: %q", joined)
	}
	// Warnings are drained once read, so a caller cannot log them twice.
	if len(store.Warnings()) != 0 {
		t.Error("warnings were not cleared after reading")
	}
}
