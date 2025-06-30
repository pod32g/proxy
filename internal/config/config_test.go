package config

import (
	log "github.com/pod32g/simple-logger"
	"strings"
	"testing"
)

func TestHeaderManagement(t *testing.T) {
	cfg := &Config{}
	cfg.SetHeader("A", "1")
	cfg.SetClientHeader("client1", "B", "2")
	hdrs := cfg.GetHeadersForClient("client1")
	if hdrs["A"] != "1" || hdrs["B"] != "2" {
		t.Fatalf("unexpected headers: %#v", hdrs)
	}
	cfg.DeleteClientHeader("client1", "B")
	hdrs = cfg.GetHeadersForClient("client1")
	if _, ok := hdrs["B"]; ok {
		t.Fatalf("client header not deleted")
	}
	cfg.DeleteHeader("A")
	if len(cfg.GetHeaders()) != 0 {
		t.Fatalf("expected global header deleted")
	}
}

func TestLogLevelParseAndString(t *testing.T) {
	levels := []struct {
		str string
		lvl log.LogLevel
	}{
		{"DEBUG", log.DEBUG},
		{"INFO", log.INFO},
		{"WARN", log.WARN},
		{"ERROR", log.ERROR},
		{"FATAL", log.FATAL},
		{"OTHER", log.INFO},
	}
	for _, tt := range levels {
		if ParseLogLevel(tt.str) != tt.lvl {
			t.Fatalf("ParseLogLevel failed for %s", tt.str)
		}
		if LevelString(tt.lvl) != strings.ToUpper(tt.str) && tt.str != "OTHER" {
			t.Fatalf("LevelString failed for %s", tt.str)
		}
	}
}

func TestAuthIdentityStats(t *testing.T) {
	cfg := &Config{}
	cfg.SetAuth(true, "user", "pass")
	if e, u, p := cfg.GetAuth(); !e || u != "user" || p != "pass" {
		t.Fatalf("unexpected auth: %v %s %s", e, u, p)
	}
	cfg.SetIdentity("name", "id")
	n, id := cfg.GetIdentity()
	if n != "name" || id != "id" {
		t.Fatalf("unexpected identity")
	}
	cfg.SetStatsEnabled(true)
	if !cfg.StatsEnabledState() {
		t.Fatalf("stats not enabled")
	}
}
