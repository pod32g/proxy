package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A proxy cannot bound how long a transfer takes: WriteTimeout severed long
// downloads and the UI's own SSE streams, and ReadTimeout capped uploads.
func TestServerHasNoWholeRequestTimeouts(t *testing.T) {
	s := &Server{Handler: http.NotFoundHandler(), Clients: NewClientTracker()}
	srv := s.newHTTPServer(listener{name: "http", addr: ":0", handler: s.Handler, track: true})

	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout must stay unset, got %v", srv.WriteTimeout)
	}
	if srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout must stay unset, got %v", srv.ReadTimeout)
	}
	if srv.ReadHeaderTimeout != readHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, readHeaderTimeout)
	}
	if srv.IdleTimeout != idleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, idleTimeout)
	}
	if srv.ConnState == nil {
		t.Error("connection tracking not wired up")
	}
}

func TestListenersDefaultToOneHTTP(t *testing.T) {
	s := &Server{HTTPAddr: ":8080", Handler: http.NotFoundHandler()}
	got, err := s.listeners()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].name != "http" || got[0].tls() {
		t.Fatalf("unexpected listeners: %+v", got)
	}
	if !got[0].track {
		t.Error("proxy connections must count towards the client gauge")
	}
}

// Half-configured TLS on either listener is a startup error, not a silent
// fall back to plaintext.
func TestListenersRejectHalfConfiguredTLS(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    Server
	}{
		{"https without cert or key", Server{HTTPAddr: ":8080", HTTPSAddr: ":8443"}},
		{"https without key", Server{HTTPAddr: ":8080", HTTPSAddr: ":8443", CertFile: "c"}},
		{"admin cert without key", Server{
			HTTPAddr: ":8080", AdminAddr: ":9000",
			AdminHandler: http.NotFoundHandler(), AdminCertFile: "c",
		}},
		{"admin key without cert", Server{
			HTTPAddr: ":8080", AdminAddr: ":9000",
			AdminHandler: http.NotFoundHandler(), AdminKeyFile: "k",
		}},
		{"admin without a handler", Server{HTTPAddr: ":8080", AdminAddr: ":9000"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.s.Handler = http.NotFoundHandler()
			if _, err := tc.s.listeners(); err == nil {
				t.Error("accepted a configuration that cannot work")
			}
		})
	}
}

// Admin traffic is an operator with a browser open, not a proxy client, so it
// must not inflate the connected-clients number the UI reports.
func TestAdminListenerIsNotCountedAsAClient(t *testing.T) {
	s := &Server{
		HTTPAddr: ":8080", Handler: http.NotFoundHandler(),
		AdminAddr: ":9000", AdminHandler: http.NotFoundHandler(),
	}
	got, err := s.listeners()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d listeners, want 2", len(got))
	}
	admin := got[1]
	if admin.name != "admin" || admin.track {
		t.Errorf("admin listener: %+v", admin)
	}
}

// With the admin surface split off, the proxy port must proxy those paths
// rather than answering them.
func TestSplitAdminSurfaceRouting(t *testing.T) {
	proxyOnly := &Router{Proxy: okHandler("PROXIED"), HealthPath: DefaultHealthPath}
	adminOnly := &Router{
		UI: okHandler("ADMIN-UI"), API: okHandler("ADMIN-API"),
		Metrics: okHandler("ADMIN-METRICS"), HealthPath: DefaultHealthPath,
	}

	for _, path := range []string{"/ui/general", "/api/headers", "/metrics"} {
		rec := httptest.NewRecorder()
		proxyOnly.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Body.String() != "PROXIED" {
			t.Errorf("proxy port %s: got %q, want it proxied", path, rec.Body.String())
		}
	}

	for _, tc := range []struct{ path, want string }{
		{"/ui/general", "ADMIN-UI"},
		{"/api/headers", "ADMIN-API"},
		{"/metrics", "ADMIN-METRICS"},
	} {
		rec := httptest.NewRecorder()
		adminOnly.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Body.String() != tc.want {
			t.Errorf("admin port %s: got %q, want %q", tc.path, rec.Body.String(), tc.want)
		}
	}

	// Health answers on both, so a probe can target either listener.
	for name, r := range map[string]*Router{"proxy": proxyOnly, "admin": adminOnly} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
			t.Errorf("%s health: got %d %q", name, rec.Code, rec.Body.String())
		}
	}

	// An unmatched path on the admin listener has nowhere to go.
	rec := httptest.NewRecorder()
	adminOnly.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("admin port unmatched path: got %d, want 404", rec.Code)
	}
}
