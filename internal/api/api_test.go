package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
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

// A cross-origin form POST is the shape that reaches an API without a CORS
// preflight; it must not be honoured just because the caller is authenticated.
func TestGuardRejectsCrossOriginAndFormPosts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		origin      string
		contentType string
		want        int
	}{
		{"json, no origin", "", "application/json", http.StatusNoContent},
		{"json, same origin", "http://example.com", "application/json", http.StatusNoContent},
		{"json with charset", "", "application/json; charset=utf-8", http.StatusNoContent},
		{"cross origin", "http://evil.test", "application/json", http.StatusForbidden},
		{"form encoded", "", "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"text plain", "", "text/plain", http.StatusUnsupportedMediaType},
		{"no content type", "", "", http.StatusUnsupportedMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, h := newAPI()
			var buf bytes.Buffer
			json.NewEncoder(&buf).Encode(map[string]string{"name": "A", "value": "1"})
			req := httptest.NewRequest("POST", "/headers", &buf)
			req.Host = "example.com"
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d", rec.Code, tc.want)
			}
			mutated := len(cfg.GetHeaders()) > 0
			if mutated != (tc.want == http.StatusNoContent) {
				t.Fatalf("config mutated=%v for status %d", mutated, rec.Code)
			}
		})
	}
}

// Reads stay open to cross-origin callers; only mutations are gated.
func TestGuardAllowsReads(t *testing.T) {
	_, h := newAPI()
	req := httptest.NewRequest("GET", "/headers", nil)
	req.Header.Set("Origin", "http://evil.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

// An invalid level is a caller error, not a reason to silently drop to INFO.
func TestLogLevelRejectsInvalid(t *testing.T) {
	cfg, h := newAPI()
	cfg.SetLogLevel(config.ParseLogLevel("ERROR"))
	rec := doReq(t, h, "POST", "/loglevel", map[string]string{"level": "VERBOSE"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if cfg.GetLogLevel() != config.ParseLogLevel("ERROR") {
		t.Fatal("invalid level changed the configured level")
	}
}

// A body that fails to parse must not be applied as a set of zero values. This
// used to turn authentication off and answer 204.
func TestMalformedBodyIsRejected(t *testing.T) {
	for _, path := range []string{"/auth", "/stats", "/headers", "/identity", "/loglevel"} {
		t.Run(path, func(t *testing.T) {
			cfg, h := newAPI()
			cfg.SetAuth(true, "alice", "s3cret")
			cfg.SetStatsEnabled(true)

			req := httptest.NewRequest("POST", path, strings.NewReader("{ not json"))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400", rec.Code)
			}
			if enabled, _, _ := cfg.GetAuth(); !enabled {
				t.Error("a malformed body disabled authentication")
			}
			if !cfg.StatsEnabledState() {
				t.Error("a malformed body disabled stats")
			}
		})
	}
}

// An omitted boolean is not the same as an explicit false: absent means "say
// what you mean", not "turn it off".
func TestBooleanFieldsMustBePresent(t *testing.T) {
	cfg, h := newAPI()
	cfg.SetAuth(true, "alice", "s3cret")

	rec := doReq(t, h, "POST", "/auth", map[string]string{"username": "bob"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if enabled, user, _ := cfg.GetAuth(); !enabled || user != "alice" {
		t.Fatalf("request was partially applied: enabled=%v user=%q", enabled, user)
	}

	// Explicitly false still works.
	rec2 := doReq(t, h, "POST", "/auth", map[string]interface{}{"enabled": false})
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("explicit false: got %d", rec2.Code)
	}
	if enabled, _, _ := cfg.GetAuth(); enabled {
		t.Error("explicit false was not applied")
	}
}

// Bodies are capped so a config endpoint cannot be used to make the proxy
// allocate without limit.
func TestOversizedBodyIsRejected(t *testing.T) {
	_, h := newAPI()
	req := httptest.NewRequest("POST", "/headers",
		strings.NewReader(`{"name":"X","value":"`+strings.Repeat("a", maxBodyBytes+1024)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}
