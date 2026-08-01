package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// postForm submits a form the way a browser that has loaded a UI page would:
// with the CSRF cookie set and the matching token echoed in the body.
func postForm(t *testing.T, h http.Handler, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	const token = "test-csrf-token"
	values.Set(csrfFieldName, token)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAddAndDeleteHeader(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)

	rec := postForm(t, h, "/header", url.Values{"name": {"A"}, "value": {"1"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	if v := cfg.GetHeaders()["A"]; v != "1" {
		t.Fatalf("header not set: %v", cfg.GetHeaders())
	}

	rec2 := postForm(t, h, "/delete", url.Values{"name": {"A"}})
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

	rec := postForm(t, h, "/loglevel", url.Values{"level": {"DEBUG"}})
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

	rec := postForm(t, h, "/set-identity", url.Values{"name": {"N"}, "id": {"ID"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	n, id := cfg.GetIdentity()
	if n != "N" || id != "ID" {
		t.Fatalf("identity not set: %s %s", n, id)
	}

	rec2 := postForm(t, h, "/stats", url.Values{"enabled": {"on"}})
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

// The Authentication page's Save button must actually save. The handler existed
// but was never routed, so the form 404'd and silently discarded the change.
func TestSetAuthSaves(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)

	rec := postForm(t, h, "/set-auth", url.Values{
		"enabled": {"on"}, "username": {"alice"}, "password": {"s3cret"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	enabled, user, pass := cfg.GetAuth()
	if !enabled || user != "alice" || pass != "s3cret" {
		t.Fatalf("auth not saved: %v %q %q", enabled, user, pass)
	}

	// A blank password means "leave it alone", not "clear it".
	rec2 := postForm(t, h, "/set-auth", url.Values{
		"enabled": {"on"}, "username": {"bob"}, "password": {""},
	})
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec2.Code)
	}
	_, user, pass = cfg.GetAuth()
	if user != "bob" || pass != "s3cret" {
		t.Fatalf("blank password should preserve the old one: %q %q", user, pass)
	}

	// Unticking the box disables auth.
	postForm(t, h, "/set-auth", url.Values{"username": {"bob"}})
	if enabled, _, _ := cfg.GetAuth(); enabled {
		t.Fatal("auth should be disabled when the checkbox is absent")
	}
}

// Every mutating route must reject a request that cannot prove it came from the
// UI, since basic-auth credentials ride along on cross-site requests.
func TestMutatingRoutesRequireCSRF(t *testing.T) {
	paths := map[string]url.Values{
		"/header":       {"name": {"X"}, "value": {"1"}},
		"/delete":       {"name": {"X"}},
		"/loglevel":     {"level": {"DEBUG"}},
		"/set-identity": {"name": {"N"}, "id": {"I"}},
		"/set-auth":     {"username": {"u"}, "password": {"p"}},
		"/stats":        {"enabled": {"on"}},
	}
	for path, values := range paths {
		t.Run(path, func(t *testing.T) {
			cfg := &config.Config{}
			h := New(cfg, nil, nil, nil, nil)

			// No cookie, no token at all.
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("no CSRF material: expected 403, got %d", rec.Code)
			}

			// Cookie present but the form token does not match it — the shape a
			// cross-site POST takes, since the attacker cannot read the cookie.
			mismatched := url.Values{}
			for k, v := range values {
				mismatched[k] = v
			}
			mismatched.Set(csrfFieldName, "attacker-guess")
			req2 := httptest.NewRequest(http.MethodPost, path, strings.NewReader(mismatched.Encode()))
			req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req2.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "real-token"})
			rec2 := httptest.NewRecorder()
			h.ServeHTTP(rec2, req2)
			if rec2.Code != http.StatusForbidden {
				t.Errorf("mismatched token: expected 403, got %d", rec2.Code)
			}

			if len(cfg.GetHeaders()) != 0 {
				t.Error("rejected request still mutated config")
			}
			if enabled, _, _ := cfg.GetAuth(); enabled {
				t.Error("rejected request still enabled auth")
			}
		})
	}
}

// Rendering a page hands the browser a token it can echo back.
func TestPagesIssueCSRFToken(t *testing.T) {
	for _, path := range []string{"/general", "/analytics", "/identity", "/auth"} {
		t.Run(path, func(t *testing.T) {
			h := New(&config.Config{}, nil, nil, nil, nil)
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("got %d", rec.Code)
			}
			var token string
			for _, c := range rec.Result().Cookies() {
				if c.Name == csrfCookieName {
					token = c.Value
					if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/ui" {
						t.Errorf("weak cookie attributes: %+v", c)
					}
				}
			}
			if token == "" {
				t.Fatal("no CSRF cookie issued")
			}
			if !strings.Contains(rec.Body.String(), token) {
				t.Error("token not embedded in the page's forms")
			}
		})
	}
}

// An existing token is reused rather than rotated on every render, otherwise a
// second tab would invalidate the first tab's forms.
func TestCSRFTokenIsStable(t *testing.T) {
	h := New(&config.Config{}, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/general", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "existing-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName && c.Value != "existing-token" {
			t.Fatalf("token rotated to %q", c.Value)
		}
	}
	if !strings.Contains(rec.Body.String(), "existing-token") {
		t.Fatal("existing token not used in forms")
	}
}

// Rendering a page must not race with a concurrent identity save.
func TestPageRenderDoesNotRaceWithIdentitySave(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				cfg.SetIdentity("name", "id")
			}
		}
	}()
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/identity", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	close(stop)
	wg.Wait()
}

func TestPolicyPageRoundTrip(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg, nil, nil, nil, nil)

	rec := postForm(t, h, "/set-policy", url.Values{
		"destinations": {"allow domain example.com\ndeny all"},
		"clients":      {"allow 10.0.0.0/8\ndefault deny"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rec.Code, rec.Body.String())
	}
	if cfg.PolicyRulesText() == "" || cfg.ClientRulesText() == "" {
		t.Fatal("rules not applied")
	}

	// The page renders what was saved, so it can be edited further.
	req := httptest.NewRequest(http.MethodGet, "/policy", nil)
	page := httptest.NewRecorder()
	h.ServeHTTP(page, req)
	if !strings.Contains(page.Body.String(), "deny all") {
		t.Error("saved rules not shown on the page")
	}
}

// An invalid rule set must not discard what the operator typed. Redirecting
// away with the input lost is how people stop using a form.
func TestPolicyPageKeepsInputOnError(t *testing.T) {
	cfg := &config.Config{}
	if err := cfg.SetPolicyRules("allow all"); err != nil {
		t.Fatal(err)
	}
	h := New(cfg, nil, nil, nil, nil)

	rec := postForm(t, h, "/set-policy", url.Values{
		"destinations": {"allow domain example.com\nallow bogus rule"},
		"clients":      {""},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the page to be re-rendered, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "line 2") {
		t.Error("error should name the offending line")
	}
	if !strings.Contains(body, "allow bogus rule") {
		t.Error("the operator's input was discarded")
	}
	if cfg.PolicyRulesText() != "allow all" {
		t.Errorf("invalid rules were applied: %q", cfg.PolicyRulesText())
	}
}

func TestPolicyPageDryRun(t *testing.T) {
	cfg := &config.Config{}
	if err := cfg.SetPolicyRules("allow domain example.com\ndeny all"); err != nil {
		t.Fatal(err)
	}
	h := New(cfg, nil, nil, nil, nil)

	rec := postForm(t, h, "/test-policy", url.Values{"host": {"api.example.com"}})
	if !strings.Contains(rec.Body.String(), "ALLOWED") {
		t.Errorf("allowed host: %q", rec.Body.String())
	}
	rec2 := postForm(t, h, "/test-policy", url.Values{"host": {"elsewhere.test"}})
	body := rec2.Body.String()
	if !strings.Contains(body, "DENIED") || !strings.Contains(body, "deny all") {
		t.Errorf("denied host should name the rule: %q", body)
	}
}
