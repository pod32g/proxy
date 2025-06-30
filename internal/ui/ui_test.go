package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/server"
	log "github.com/pod32g/simple-logger"
)

func TestIndexRedirect(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
}

func TestEventsUnavailable(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/events", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestStatsEventsUnavailable(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, server.NewDomainStats())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/stats-events", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestAddAndDeleteHeader(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/header", strings.NewReader("name=A&value=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	if v := cfg.GetHeaders()["A"]; v != "1" {
		t.Fatalf("header not set: %v", cfg.GetHeaders())
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/delete", strings.NewReader("name=A"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec2.Code)
	}
	if _, ok := cfg.GetHeaders()["A"]; ok {
		t.Fatalf("header not deleted")
	}
}

func TestSetLogLevel(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/loglevel", strings.NewReader("level=DEBUG"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	if lvl := cfg.GetLogLevel(); lvl != log.DEBUG {
		t.Fatalf("unexpected log level: %v", lvl)
	}
}

func TestSetIdentityAndStats(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/set-identity", strings.NewReader("name=N&id=ID"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	n, id := cfg.GetIdentity()
	if n != "N" || id != "ID" {
		t.Fatalf("identity not set: %s %s", n, id)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/stats", strings.NewReader("enabled=on"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec2.Code)
	}
	if !cfg.StatsEnabledState() {
		t.Fatalf("stats not enabled")
	}
}
