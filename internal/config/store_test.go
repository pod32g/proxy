package config

import (
	log "github.com/pod32g/simple-logger"
	"os"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	enc, err := encrypt("key", "data")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decrypt("key", enc)
	if err != nil || dec != "data" {
		t.Fatalf("decrypt mismatch: %v %s", err, dec)
	}
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
	if err := store.Save(cfg); err != nil {
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
