package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/server"
)

func newAuditedAPI(t *testing.T) (*config.Config, *config.Store, http.Handler) {
	t.Helper()
	store, err := config.NewStore(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := &config.Config{}
	return cfg, store, New(cfg, store, nil, server.NewDomainStats())
}

// doAudited sends a request from a known address with known credentials, so the
// recorded actor can be asserted rather than assumed.
func doAudited(t *testing.T, h http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.RemoteAddr = "10.1.2.3:5000"
	req.SetBasicAuth("operator", "irrelevant-here")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Every mutating endpoint must leave a trail. The criterion this covers is the
// strong one: an audit that misses a path is worse than no audit, because it
// implies a completeness it does not have.
//
// Coverage is structural — the trail is written inside Store.Save, so any path
// that persists is recorded — and this checks the other half, that each endpoint
// actually persists rather than mutating only the in-memory config.
func TestEveryMutatingEndpointIsAudited(t *testing.T) {
	for _, tc := range []struct {
		name    string
		method  string
		path    string
		body    interface{}
		setting string
	}{
		{"log level", "POST", "/loglevel", map[string]string{"level": "DEBUG"}, "log_level"},
		{"identity", "POST", "/identity", map[string]string{"name": "edge-1", "id": "abc"}, "proxy_name"},
		{"stats", "POST", "/stats", map[string]bool{"enabled": true}, "stats_enabled"},
		{"credentials", "POST", "/auth",
			map[string]interface{}{"enabled": true, "username": "u", "password": "p"}, "password"},
		{"destination policy", "PUT", "/policy",
			map[string]string{"destinations": "deny all"}, "policy_rules"},
		{"client policy", "PUT", "/policy",
			map[string]string{"clients": "deny 10.9.9.9"}, "client_rules"},
		{"quotas", "PUT", "/policy",
			map[string]string{"quotas": "client requests 10/s"}, "quota_rules"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, store, h := newAuditedAPI(t)

			rec := doAudited(t, h, tc.method, tc.path, tc.body)
			if rec.Code >= 400 {
				t.Fatalf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
			}

			entries, err := store.Audit(50)
			if err != nil {
				t.Fatalf("Audit: %v", err)
			}
			var found *config.AuditEntry
			for i := range entries {
				if entries[i].Setting == tc.setting {
					found = &entries[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("%s produced no audit entry for %q; got %+v", tc.name, tc.setting, entries)
			}
			if found.Via != config.ViaAPI {
				t.Errorf("via = %q, want %q", found.Via, config.ViaAPI)
			}
			if found.User != "operator" {
				t.Errorf("user = %q, want the authenticated caller", found.User)
			}
			if found.Source != "10.1.2.3" {
				t.Errorf("source = %q, want the bare client address", found.Source)
			}
		})
	}
}

// Headers live in their own table rather than settings, so they take a
// different path through Save and are worth asserting separately.
func TestHeaderChangesReachTheStore(t *testing.T) {
	cfg, store, h := newAuditedAPI(t)
	rec := doAudited(t, h, "POST", "/headers", map[string]string{"name": "X-A", "value": "1"})
	if rec.Code >= 400 {
		t.Fatalf("POST /headers: %d", rec.Code)
	}
	if cfg.GetHeaders()["X-A"] != "1" {
		t.Fatal("header not applied")
	}
	// Reload into a fresh config to prove it was persisted, which is what makes
	// the audit path run at all.
	reloaded := &config.Config{}
	if err := store.Load(reloaded); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reloaded.GetHeaders()["X-A"] != "1" {
		t.Error("header did not reach the store")
	}
}

func TestAuditEndpointIsReadOnly(t *testing.T) {
	_, _, h := newAuditedAPI(t)

	// Make a change so there is something to read.
	doAudited(t, h, "POST", "/identity", map[string]string{"name": "edge-1"})

	rec := doAudited(t, h, "GET", "/audit", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /audit: %d %s", rec.Code, rec.Body.String())
	}
	var entries []config.AuditEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if len(entries) == 0 {
		t.Fatal("no entries returned")
	}

	// Nothing may edit or remove an entry: a trail somebody can rewrite is not
	// one an investigation can rely on.
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		rec := doAudited(t, h, method, "/audit", map[string]string{"x": "y"})
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /audit returned %d, want 405", method, rec.Code)
		}
	}
}

func TestAuditEndpointWithoutStore(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, server.NewDomainStats())
	rec := doAudited(t, h, "GET", "/audit", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want an empty list rather than an error", rec.Code)
	}
	if got := rec.Body.String(); got != "[]\n" {
		t.Errorf("body = %q, want an empty JSON array", got)
	}
}
