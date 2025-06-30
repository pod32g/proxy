package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatsMiddleware(t *testing.T) {
	ds := NewDomainStats()
	mw := StatsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), ds, func() bool { return true }, func(r *http.Request) string { return r.Host })
	req := httptest.NewRequest("GET", "http://example.com:8080/", nil)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)
	top := ds.Top(1)
	if len(top) != 1 || top[0].Host != "example.com" {
		t.Fatalf("stats not recorded: %v", top)
	}
}

func TestStatsMiddlewareDisabled(t *testing.T) {
	ds := NewDomainStats()
	mw := StatsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), ds, func() bool { return false }, func(r *http.Request) string { return r.Host })
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)
	if len(ds.Top(1)) != 0 {
		t.Fatalf("stats should be empty")
	}
}
