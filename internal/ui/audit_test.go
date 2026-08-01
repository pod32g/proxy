package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pod32g/proxy/internal/config"
)

func newAuditedUI(t *testing.T) (*config.Config, *config.Store, http.Handler) {
	t.Helper()
	store, err := config.NewStore(filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := &config.Config{}
	return cfg, store, New(cfg, store, nil, nil, nil)
}

// postAuditedForm sends a CSRF-valid form from a known address with known credentials,
// so the recorded actor can be asserted rather than assumed.
func postAuditedForm(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	const token = "test-csrf-token"
	form.Set(csrfFieldName, token)

	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	req.RemoteAddr = "10.1.2.3:5000"
	req.SetBasicAuth("operator", "irrelevant-here")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The UI is the other surface that mutates configuration, so it needs the same
// guarantee the API has: nothing changes without a trail entry naming who did it.
func TestEveryMutatingFormIsAudited(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		form    url.Values
		setting string
	}{
		{"log level", "/loglevel", url.Values{"level": {"DEBUG"}}, "log_level"},
		{"identity", "/set-identity", url.Values{"name": {"edge-1"}, "id": {"abc"}}, "proxy_name"},
		{"stats", "/stats", url.Values{"enabled": {"on"}}, "stats_enabled"},
		{"credentials", "/set-auth",
			url.Values{"enabled": {"on"}, "username": {"u"}, "password": {"p"}}, "password"},
		{"policy", "/set-policy",
			url.Values{"destinations": {"deny all"}, "clients": {""}, "quotas": {""}}, "policy_rules"},
		{"quotas", "/set-policy",
			url.Values{"destinations": {""}, "clients": {""}, "quotas": {"client requests 10/s"}}, "quota_rules"},
		{"header", "/header", url.Values{"name": {"X-A"}, "value": {"1"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, store, h := newAuditedUI(t)

			rec := postAuditedForm(t, h, tc.path, tc.form)
			if rec.Code >= 400 {
				t.Fatalf("POST %s: %d %s", tc.path, rec.Code, rec.Body.String())
			}
			if tc.setting == "" {
				// Headers live in their own table; nothing to assert in the
				// settings diff, and the API test covers persistence.
				return
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
			if found.Via != config.ViaUI {
				t.Errorf("via = %q, want %q", found.Via, config.ViaUI)
			}
			if found.User != "operator" || found.Source != "10.1.2.3" {
				t.Errorf("actor = %+v, want operator from 10.1.2.3", found)
			}
		})
	}
}

func TestAuditPageRendersEntries(t *testing.T) {
	_, _, h := newAuditedUI(t)
	postAuditedForm(t, h, "/set-identity", url.Values{"name": {"edge-1"}})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/audit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /audit: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"proxy_name", "edge-1", "operator", "10.1.2.3", config.ViaUI} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page missing %q", want)
		}
	}
}

// A page that changes the trail would defeat the point of having one.
func TestAuditPageIsReadOnly(t *testing.T) {
	_, _, h := newAuditedUI(t)
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/audit", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /audit returned %d, want 405", method, rec.Code)
		}
	}
}

// The password an operator types into the form must not come back out on the
// page that lists what changed.
func TestAuditPageNeverShowsACredential(t *testing.T) {
	const secret = "hunter2-do-not-render-me"
	_, _, h := newAuditedUI(t)
	postAuditedForm(t, h, "/set-auth",
		url.Values{"enabled": {"on"}, "username": {"svc-user"}, "password": {secret}})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/audit", nil))
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Error("the audit page rendered the password")
	}
	if strings.Contains(body, "svc-user") {
		t.Error("the audit page rendered the username")
	}
	if !strings.Contains(body, "password") {
		t.Error("the password change is not shown at all; it must be, just without the value")
	}
}
