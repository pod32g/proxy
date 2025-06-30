package ui

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/pod32g/proxy/internal/config"
    "github.com/pod32g/proxy/internal/server"
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
