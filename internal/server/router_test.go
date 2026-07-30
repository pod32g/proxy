package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func staticAuth(enabled bool, user, pass string) func() (bool, string, string) {
	return func() (bool, string, string) { return enabled, user, pass }
}

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
}

func TestRouterAuth(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, "user", "pass")}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.SetBasicAuth("user", "pass")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}

	cred := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("Proxy-Authorization", "Basic "+cred)
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec3.Code)
	}

	// Right user, wrong password must not pass.
	req4 := httptest.NewRequest("GET", "/", nil)
	req4.SetBasicAuth("user", "wrong")
	rec4 := httptest.NewRecorder()
	r.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bad password, got %d", rec4.Code)
	}
}

func TestRouterAuthDisabled(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(false, "user", "pass")}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// Auth is consulted per request, so credentials changed at runtime take effect
// without a restart and a revoked password stops working immediately.
func TestRouterAuthIsLive(t *testing.T) {
	user, pass := "alice", "s3cret"
	r := &Router{
		Proxy: okHandler("proxied"),
		Auth:  func() (bool, string, string) { return true, user, pass },
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("alice", "s3cret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the original password to work, got %d", rec.Code)
	}

	pass = "rotated"

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.SetBasicAuth("alice", "s3cret")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("revoked password still accepted: got %d", rec2.Code)
	}

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.SetBasicAuth("alice", "rotated")
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("rotated password rejected: got %d", rec3.Code)
	}
}

// Enabling auth without usable credentials must deny, not wave everything through.
func TestRouterAuthFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, user, pass string }{
		{"empty username", "", "s3cret"},
		{"empty password", "alice", ""},
		{"both empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, tc.user, tc.pass)}
			req := httptest.NewRequest("GET", "/", nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", rec.Code)
			}
			// Supplying the partial credential must not help either.
			req2 := httptest.NewRequest("GET", "/", nil)
			req2.SetBasicAuth(tc.user, tc.pass)
			rec2 := httptest.NewRecorder()
			r.ServeHTTP(rec2, req2)
			if rec2.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 with partial credentials, got %d", rec2.Code)
			}
		})
	}
}

// A proxy client asking for a remote URL must be proxied, even when that URL's
// path collides with the admin surface.
func TestAdminSurfaceNotReachableThroughProxy(t *testing.T) {
	r := &Router{
		Proxy:   okHandler("PROXIED"),
		API:     okHandler("ADMIN-API"),
		UI:      okHandler("ADMIN-UI"),
		Metrics: okHandler("ADMIN-METRICS"),
	}
	for _, target := range []string{
		"http://example.com/api/headers",
		"http://example.com/ui/general",
		"http://example.com/ui",
		"http://example.com/metrics",
		"http://example.com/healthz",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if got := rec.Body.String(); got != "PROXIED" {
			t.Errorf("%s: expected the request to be proxied, got %q", target, got)
		}
	}
}

// Addressed directly, the same paths still serve the admin surface.
func TestAdminSurfaceReachableDirectly(t *testing.T) {
	r := &Router{
		Proxy:   okHandler("PROXIED"),
		API:     okHandler("ADMIN-API"),
		UI:      okHandler("ADMIN-UI"),
		Metrics: okHandler("ADMIN-METRICS"),
	}
	for _, tc := range []struct{ path, want string }{
		{"/api/headers", "ADMIN-API"},
		{"/ui/general", "ADMIN-UI"},
		{"/metrics", "ADMIN-METRICS"},
		{"/anything-else", "PROXIED"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if got := rec.Body.String(); got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.path, tc.want, got)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("/ui should redirect, got %d", rec.Code)
	}
}

// Probes must work without credentials; nothing else may.
func TestHealthzBypassesAuth(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, "user", "pass")}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("healthz: got %d %q", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("healthz exemption leaked to other paths: got %d", rec2.Code)
	}
}

func TestProxyBasicAuthParsing(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		user, pass   string
		ok           bool
	}{
		{"valid", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p")), "u", "p", true},
		{"lowercase scheme", "basic " + base64.StdEncoding.EncodeToString([]byte("u:p")), "u", "p", true},
		{"password with colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p:q")), "u", "p:q", true},
		{"empty", "", "", "", false},
		{"not base64", "Basic !!!!", "", "", false},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), "", "", false},
		{"wrong scheme", "Bearer abc", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				req.Header.Set("Proxy-Authorization", tc.header)
			}
			user, pass, ok := proxyBasicAuth(req)
			if ok != tc.ok || user != tc.user || pass != tc.pass {
				t.Fatalf("got (%q, %q, %v), want (%q, %q, %v)", user, pass, ok, tc.user, tc.pass, tc.ok)
			}
		})
	}
}
