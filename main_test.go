package main

import (
	"testing"

	"github.com/pod32g/proxy/internal/config"
	log "github.com/pod32g/simple-logger"
)

func TestEnvironmentGet(t *testing.T) {
	key := "TEST_ENV_VAR"
	env := newEnvironment()
	if got := env.get(key, "default"); got != "default" {
		t.Fatalf("expected default, got %s", got)
	}
	if env.set[key] {
		t.Fatal("an unset variable must not be recorded as supplied")
	}
	t.Setenv(key, "value")
	if got := env.get(key, "default"); got != "value" {
		t.Fatalf("expected value, got %s", got)
	}
	if !env.set[key] {
		t.Fatal("a supplied variable must be recorded so it outranks stored config")
	}
}

func TestHeaderFlags(t *testing.T) {
	var h headerFlags
	if err := h.Set("A=1"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}
	if h.String() != "A=1" {
		t.Fatalf("unexpected string: %s", h.String())
	}
	if err := h.Set("badformat"); err == nil {
		t.Fatalf("expected error for bad format")
	}
}

// Explicit flags and environment variables must survive Store.Load, which
// otherwise overwrites everything it finds in the database.
func TestReapplyRestoresExplicitSettings(t *testing.T) {
	cli := startupValues{
		logLevel:     log.DEBUG,
		authEnabled:  true,
		username:     "flag-user",
		password:     "flag-pass",
		proxyName:    "flag-name",
		proxyID:      "flag-id",
		statsEnabled: true,
	}

	// Stand in for a config that Load has just populated from the database.
	stored := func() *config.Config {
		c := &config.Config{}
		c.SetLogLevel(log.ERROR)
		c.SetAuthEnabled(false)
		c.SetCredentials("db-user", "db-pass")
		c.SetProxyName("db-name")
		c.SetProxyID("db-id")
		c.SetStatsEnabled(false)
		return c
	}

	t.Run("flag wins over stored", func(t *testing.T) {
		cfg := stored()
		reapply(cfg, cli, overrides{
			flags: map[string]bool{
				"log-level": true, "auth": true, "auth-user": true, "auth-pass": true,
				"proxy-name": true, "proxy-id": true, "stats": true,
			},
			envs: map[string]bool{},
		})
		if cfg.GetLogLevel() != log.DEBUG {
			t.Errorf("log level: got %v", cfg.GetLogLevel())
		}
		enabled, user, pass := cfg.GetAuth()
		if !enabled || user != "flag-user" || pass != "flag-pass" {
			t.Errorf("auth: got %v %q %q", enabled, user, pass)
		}
		name, id := cfg.GetIdentity()
		if name != "flag-name" || id != "flag-id" {
			t.Errorf("identity: got %q %q", name, id)
		}
		if !cfg.StatsEnabledState() {
			t.Error("stats not re-applied")
		}
	})

	t.Run("env wins over stored", func(t *testing.T) {
		cfg := stored()
		reapply(cfg, cli, overrides{
			flags: map[string]bool{},
			envs:  map[string]bool{"PROXY_NAME": true, "PROXY_LOG_LEVEL": true},
		})
		if cfg.GetLogLevel() != log.DEBUG {
			t.Errorf("log level: got %v", cfg.GetLogLevel())
		}
		if name, _ := cfg.GetIdentity(); name != "flag-name" {
			t.Errorf("proxy name: got %q", name)
		}
		// Untouched settings keep the stored value.
		if _, id := cfg.GetIdentity(); id != "db-id" {
			t.Errorf("proxy id should still be stored value, got %q", id)
		}
	})

	t.Run("stored wins when nothing was supplied", func(t *testing.T) {
		cfg := stored()
		reapply(cfg, cli, overrides{flags: map[string]bool{}, envs: map[string]bool{}})
		if cfg.GetLogLevel() != log.ERROR {
			t.Errorf("log level: got %v", cfg.GetLogLevel())
		}
		enabled, user, pass := cfg.GetAuth()
		if enabled || user != "db-user" || pass != "db-pass" {
			t.Errorf("auth: got %v %q %q", enabled, user, pass)
		}
		if cfg.StatsEnabledState() {
			t.Error("stats should still be the stored value")
		}
	})

	// Setting only the username must not blank the stored password.
	t.Run("half a credential pair", func(t *testing.T) {
		cfg := stored()
		reapply(cfg, cli, overrides{
			flags: map[string]bool{"auth-user": true},
			envs:  map[string]bool{},
		})
		_, user, pass := cfg.GetAuth()
		if user != "flag-user" || pass != "db-pass" {
			t.Errorf("got %q %q, want flag-user / db-pass", user, pass)
		}
	})
}
