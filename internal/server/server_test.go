package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	log "github.com/pod32g/simple-logger"
)

// testLogger discards output: these tests assert on behaviour, not on what was
// written about it.
func testLogger() *log.Logger {
	l, err := log.New(log.WithOutput(io.Discard), log.WithLevel(log.ERROR))
	if err != nil {
		panic(err)
	}
	return l
}

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

// The criterion: a listener that cannot bind is a startup error, not a partial
// start. Binding inside the serving goroutines — as this used to — meant the
// process served real requests on the working listeners for however long it
// took the broken one to fail.
func TestBindFailureServesNothing(t *testing.T) {
	// Occupy an address so a listener configured for it cannot bind.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer taken.Close()

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	freeAddr := free.Addr().String()
	free.Close()

	var served atomic.Int64
	count := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served.Add(1) })

	s := &Server{
		HTTPAddr: freeAddr,
		Handler:  count,
		Logger:   testLogger(),
		Extra: []Listener{
			{Name: "second", Addr: taken.Addr().String(), Handler: count},
		},
	}

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start() }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Start succeeded with an unbindable listener")
		}
		if !strings.Contains(err.Error(), "second") {
			t.Errorf("error does not name the failing listener: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return")
	}

	// The working listener must never have accepted anything, and its address
	// must be free again rather than left bound by a leaked socket.
	if n := served.Load(); n != 0 {
		t.Errorf("%d requests were served before the start failed", n)
	}
	reclaim, err := net.Listen("tcp", freeAddr)
	if err != nil {
		t.Errorf("the already-bound socket was leaked: %v", err)
	} else {
		reclaim.Close()
	}
}

// Two listeners on one address is not a configuration anyone means: one wins
// the bind and the other's rules silently never apply.
func TestDuplicateAddressIsRejected(t *testing.T) {
	s := &Server{
		HTTPAddr: "127.0.0.1:18123",
		Handler:  okHandler("A"),
		Logger:   testLogger(),
		Extra:    []Listener{{Name: "second", Addr: "127.0.0.1:18123", Handler: okHandler("B")}},
	}
	_, err := s.listeners()
	if err == nil {
		t.Fatal("accepted two listeners on one address")
	}
	if !strings.Contains(err.Error(), "18123") {
		t.Errorf("error does not name the address: %v", err)
	}
}

func TestExtraListenersAreValidated(t *testing.T) {
	for name, extra := range map[string]Listener{
		"no name":    {Addr: "127.0.0.1:1", Handler: okHandler("x")},
		"no address": {Name: "a", Handler: okHandler("x")},
		"no handler": {Name: "a", Addr: "127.0.0.1:1"},
		"half TLS":   {Name: "a", Addr: "127.0.0.1:1", Handler: okHandler("x"), CertFile: "c"},
	} {
		t.Run(name, func(t *testing.T) {
			s := &Server{HTTPAddr: "127.0.0.1:2", Handler: okHandler("x"),
				Logger: testLogger(), Extra: []Listener{extra}}
			if _, err := s.listeners(); err == nil {
				t.Error("accepted an invalid listener")
			}
		})
	}
}

// Every listener drains on shutdown, including the extras.
func TestShutdownDrainsEveryListener(t *testing.T) {
	addrs := make([]string, 2)
	for i := range addrs {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addrs[i] = ln.Addr().String()
		ln.Close()
	}

	s := &Server{
		HTTPAddr: addrs[0],
		Handler:  okHandler("main"),
		Logger:   testLogger(),
		Extra:    []Listener{{Name: "second", Addr: addrs[1], Handler: okHandler("second")}},
	}

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start() }()

	// Both must be answering before the shutdown is meaningful.
	for _, addr := range addrs {
		if !waitForServer(t, addr) {
			t.Fatalf("%s never started serving", addr)
		}
	}

	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete")
	}

	// Both addresses must be released, not just the first.
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("%s was not released on shutdown: %v", addr, err)
			continue
		}
		ln.Close()
	}
}

func waitForServer(t *testing.T, addr string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
