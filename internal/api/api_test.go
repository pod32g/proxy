package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/server"
)

func newAPI() (*config.Config, http.Handler) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, server.NewDomainStats())
	return cfg, h
}

func doReq(t *testing.T, h http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHeadersEndpoint(t *testing.T) {
	cfg, h := newAPI()
	doReq(t, h, "POST", "/headers", map[string]string{"name": "A", "value": "1"})
	if v := cfg.GetHeaders()["A"]; v != "1" {
		t.Fatalf("header not set")
	}

	rec := doReq(t, h, "GET", "/headers", nil)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}

	doReq(t, h, "DELETE", "/headers", map[string]string{"name": "A"})
	if len(cfg.GetHeaders()) != 0 {
		t.Fatalf("header not deleted")
	}
}

func TestLogLevelEndpoint(t *testing.T) {
	cfg, h := newAPI()
	doReq(t, h, "POST", "/loglevel", map[string]string{"level": "DEBUG"})
	if cfg.GetLogLevel() != config.ParseLogLevel("DEBUG") {
		t.Fatalf("log level")
	}
	rec := doReq(t, h, "GET", "/loglevel", nil)
	if rec.Code != 200 {
		t.Fatalf("get status")
	}
}

func TestAuthEndpoint(t *testing.T) {
	cfg, h := newAPI()
	doReq(t, h, "POST", "/auth", map[string]interface{}{"enabled": true, "username": "u", "password": "p"})
	e, u, _ := cfg.GetAuth()
	if !e || u != "u" {
		t.Fatalf("auth")
	}
	rec := doReq(t, h, "GET", "/auth", nil)
	if rec.Code != 200 {
		t.Fatalf("get auth")
	}
}

func TestIdentityEndpoint(t *testing.T) {
	cfg, h := newAPI()
	doReq(t, h, "POST", "/identity", map[string]string{"name": "n", "id": "i"})
	n, id := cfg.GetIdentity()
	if n != "n" || id != "i" {
		t.Fatalf("identity")
	}
	rec := doReq(t, h, "GET", "/identity", nil)
	if rec.Code != 200 {
		t.Fatalf("get identity")
	}
}

func TestStatsEndpoint(t *testing.T) {
	cfg, h := newAPI()
	doReq(t, h, "POST", "/stats", map[string]bool{"enabled": true})
	if !cfg.StatsEnabledState() {
		t.Fatalf("stats not enabled")
	}
	rec := doReq(t, h, "GET", "/stats", nil)
	if rec.Code != 200 {
		t.Fatalf("get stats")
	}
}
