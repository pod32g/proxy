package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

type testWriter struct {
	header http.Header
	buf    strings.Builder
	status int
}

func (w *testWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *testWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *testWriter) WriteHeader(s int)           { w.status = s }
func (w *testWriter) Flush()                      {}

func TestEventsStream(t *testing.T) {
	tracker := server.NewClientTracker()
	h := &handler{cfg: &config.Config{}, clients: tracker}

	req := httptest.NewRequest("GET", "/events", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	w := &testWriter{}

	done := make(chan struct{})
	go func() {
		h.events(w, req)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	tracker.ConnState(nil, http.StateNew)
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done

	out := w.buf.String()
	if !strings.Contains(out, "data: 0") || !strings.Contains(out, "data: 1") {
		t.Fatalf("unexpected stream: %q", out)
	}
}

func TestStatsEventsStream(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetStatsEnabled(true)
	stats := server.NewDomainStats()
	h := &handler{cfg: cfg, stats: stats}

	req := httptest.NewRequest("GET", "/stats-events", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	w := &testWriter{}

	done := make(chan struct{})
	go func() {
		h.statsEvents(w, req)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	stats.Record("example.com")
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done

	if !strings.Contains(w.buf.String(), "example.com") {
		t.Fatalf("stats not streamed: %q", w.buf.String())
	}
}
