package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestPolicyEndpointRoundTrip(t *testing.T) {
	cfg, h := newAPI()

	rec := doReq(t, h, "PUT", "/policy", map[string]string{
		"destinations": "allow domain example.com\ndeny all",
		"clients":      "allow 10.0.0.0/8\ndefault deny",
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT: got %d (%s)", rec.Code, rec.Body.String())
	}
	if cfg.PolicyRulesText() == "" || cfg.ClientRulesText() == "" {
		t.Fatal("rules not applied")
	}

	rec2 := doReq(t, h, "GET", "/policy", nil)
	var got map[string]string
	if err := json.Unmarshal(rec2.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["destinations"], "deny all") || !strings.Contains(got["clients"], "default deny") {
		t.Fatalf("round trip lost rules: %v", got)
	}
}

// A half-applied policy is worse than a rejected one, so both sets are
// validated before either is installed.
func TestPolicyEndpointValidatesBeforeApplying(t *testing.T) {
	cfg, h := newAPI()
	if err := cfg.SetPolicyRules("allow all"); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, h, "PUT", "/policy", map[string]string{
		"destinations": "allow domain example.com\ndeny all", // valid
		"clients":      "allow not-an-address",               // invalid
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "clients") {
		t.Errorf("error should name the offending set: %q", rec.Body.String())
	}
	// The valid half must not have been applied.
	if cfg.PolicyRulesText() != "allow all" {
		t.Errorf("destinations were applied despite the rejection: %q", cfg.PolicyRulesText())
	}
}

// An omitted set is left alone rather than cleared.
func TestPolicyEndpointOmittedSetIsUntouched(t *testing.T) {
	cfg, h := newAPI()
	if err := cfg.SetClientRules("allow 10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "PUT", "/policy", map[string]string{"destinations": "deny all"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d", rec.Code)
	}
	if cfg.ClientRulesText() != "allow 10.0.0.0/8" {
		t.Errorf("omitted client set was cleared: %q", cfg.ClientRulesText())
	}
}

// The dry run is the ship gate for this ticket: an ordered rule set you cannot
// interrogate is guesswork.
func TestPolicyTestEndpoint(t *testing.T) {
	cfg, h := newAPI()
	if err := cfg.SetPolicyRules("deny domain blocked.test\nallow domain example.com\ndeny all"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetClientRules("deny 203.0.113.9\ndefault allow"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		body        map[string]string
		wantAllowed bool
		wantInRule  string
	}{
		{"allowed host", map[string]string{"host": "api.example.com"}, true, "allow domain example.com"},
		{"denied host", map[string]string{"host": "blocked.test"}, false, "deny domain blocked.test"},
		{"falls through to deny all", map[string]string{"host": "other.test"}, false, "deny all"},
		{"url instead of host", map[string]string{"url": "https://api.example.com/path"}, true, "allow domain example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := doReq(t, h, "POST", "/policy/test", tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("got %d (%s)", rec.Code, rec.Body.String())
			}
			var got config.PolicyDecision
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Allowed != tc.wantAllowed {
				t.Errorf("allowed = %v, want %v (%s)", got.Allowed, tc.wantAllowed, got.Reason)
			}
			// Naming the deciding rule is the whole point.
			if !strings.Contains(got.Rule, tc.wantInRule) {
				t.Errorf("rule = %q, want it to contain %q", got.Rule, tc.wantInRule)
			}
		})
	}

	// A denied client is reported as such, before destinations are considered.
	rec := doReq(t, h, "POST", "/policy/test",
		map[string]string{"host": "api.example.com", "client": "203.0.113.9"})
	var got config.PolicyDecision
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ClientAllow || !strings.Contains(got.Reason, "client refused") {
		t.Errorf("denied client: %+v", got)
	}
}

func TestPolicyTestRequiresAHost(t *testing.T) {
	_, h := newAPI()
	rec := doReq(t, h, "POST", "/policy/test", map[string]string{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

// PROXY-78. Save returns an error and every call site here used to discard it,
// so a change that could not be written answered 204 and logged nothing. The
// setting reverts at the next restart, and the audit entry — written inside the
// same transaction on purpose — is never made either.
func TestAFailedSaveIsNotReportedAsSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.db")
	store, err := config.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	if err := store.Save(cfg, config.Actor{Via: config.ViaStartup}); err != nil {
		t.Fatal(err)
	}
	// A read-only volume, or a full disk.
	for _, p := range []struct {
		path string
		mode os.FileMode
	}{{path, 0o444}, {dir, 0o555}} {
		if err := os.Chmod(p.path, p.mode); err != nil {
			t.Skipf("cannot chmod: %v", err)
		}
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755); os.Chmod(path, 0o644) })
	if store.Save(cfg, config.Actor{Via: config.ViaStartup}) == nil {
		t.Skip("the database is still writable; cannot exercise the failure")
	}

	h := New(cfg, store, nil, nil)
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/policy", `{"destinations":"deny all"}`},
		{"POST", "/auth", `{"enabled":true,"username":"a","password":"b"}`},
		{"POST", "/loglevel", `{"level":"DEBUG"}`},
		{"POST", "/identity", `{"name":"n","id":"i"}`},
		{"POST", "/stats", `{"enabled":true}`},
		{"POST", "/headers", `{"name":"X-A","value":"1"}`},
		{"DELETE", "/headers", `{"name":"X-A"}`},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("%s %s answered %d while the change could not be persisted, want 500",
					tc.method, tc.path, rec.Code)
			}
		})
	}
}
