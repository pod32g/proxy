package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestParseUpstreamHTTP2(t *testing.T) {
	for in, want := range map[string]UpstreamHTTP2{
		"":     HTTP2Auto,
		"auto": HTTP2Auto,
		"AUTO": HTTP2Auto,
		"off":  HTTP2Off,
		"h2c":  HTTP2Cleartext,
	} {
		got, err := ParseUpstreamHTTP2(in)
		if err != nil {
			t.Errorf("ParseUpstreamHTTP2(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseUpstreamHTTP2(%q) = %q, want %q", in, got, want)
		}
	}
	// A typo must not quietly speak a different protocol than was asked for.
	if _, err := ParseUpstreamHTTP2("http2"); err == nil {
		t.Error("accepted an unknown mode")
	}
}

// tlsOrigin is an HTTPS server that reports the protocol it saw.
func tlsOrigin(t *testing.T, h2 bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	}))
	if h2 {
		srv.EnableHTTP2 = true
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func originPool(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// Auto is what the default transport already did, now explicit: negotiate h2
// over TLS when the origin offers it.
func TestAutoNegotiatesHTTP2OverTLS(t *testing.T) {
	origin := tlsOrigin(t, true)

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(), HTTP2: HTTP2Auto,
			UpstreamTLS: &tls.Config{RootCAs: originPool(t, origin)},
		})

	req := httptest.NewRequest("GET", origin.URL+"/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "HTTP/2.0" {
		t.Errorf("the origin saw %q, want HTTP/2.0", got)
	}
}

// Off has to clear both levers: clearing TLSNextProto alone leaves
// ForceAttemptHTTP2 able to reinstate it.
func TestOffForcesHTTP11(t *testing.T) {
	origin := tlsOrigin(t, true)

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(), HTTP2: HTTP2Off,
			UpstreamTLS: &tls.Config{RootCAs: originPool(t, origin)},
		})

	req := httptest.NewRequest("GET", origin.URL+"/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != "HTTP/1.1" {
		t.Errorf("the origin saw %q, want HTTP/1.1", got)
	}
}

// h2c: HTTP/2 on a cleartext connection, which is the shape a reverse proxy in
// front of a modern backend usually wants.
func TestH2CSpeaksHTTP2InCleartext(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	})
	origin := httptest.NewServer(h2c.NewHandler(inner, &http2.Server{}))
	defer origin.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts(), HTTP2: HTTP2Cleartext})

	req := httptest.NewRequest("GET", origin.URL+"/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "HTTP/2.0" {
		t.Errorf("the origin saw %q, want HTTP/2.0 over cleartext", got)
	}
}

// Without h2c the same cleartext origin is spoken to over HTTP/1.1, which is
// what makes the test above about the setting rather than about the origin.
func TestCleartextIsHTTP11ByDefault(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	})
	origin := httptest.NewServer(h2c.NewHandler(inner, &http2.Server{}))
	defer origin.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts()})

	req := httptest.NewRequest("GET", origin.URL+"/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != "HTTP/1.1" {
		t.Errorf("the origin saw %q, want HTTP/1.1", got)
	}
}

// The criterion with a trap in it. "Connection: Upgrade" does not exist in
// HTTP/2 — the mechanism was replaced by extended CONNECT — so an upgrade
// issued over an h2 connection is rejected. And PROXY-47 established that a
// broken upgrade comes back as an ordinary response rather than an error, so it
// would fail silently.
func TestUpgradesStillWorkWithH2CConfigured(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "no upgrade requested", http.StatusBadRequest)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		io.WriteString(conn, "UPGRADED")
	}))
	defer origin.Close()

	// h2c configured, which would break the upgrade if it shared the transport.
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts(), HTTP2: HTTP2Cleartext})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET "+origin.URL+"/ HTTP/1.1\r\n"+
		"Host: "+strings.TrimPrefix(origin.URL, "http://")+"\r\n"+
		"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n")

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "101 Switching Protocols") {
		t.Errorf("upgrade broke with h2c configured; got:\n%s", got)
	}
}

// CONNECT does its own raw dialling and never touches a transport, so it is
// unaffected by the h2 setting — worth confirming rather than assuming.
func TestConnectUnaffectedByH2C(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "TUNNELLED")
	}()

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts(), HTTP2: HTTP2Cleartext})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "CONNECT "+ln.Addr().String()+" HTTP/1.1\r\nHost: x\r\n\r\n")

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "200") {
		t.Errorf("CONNECT broke with h2c configured: %q", string(buf[:n]))
	}
	wg.Wait()
}

// The criterion: what was negotiated has to be visible. It was previously
// discarded, so the answer simply was not available anywhere.
func TestNegotiatedProtocolIsObserved(t *testing.T) {
	origin := tlsOrigin(t, true)

	var mu sync.Mutex
	var seen []string
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(),
			UpstreamTLS: &tls.Config{RootCAs: originPool(t, origin)},
		},
		Observer{Protocol: func(p string) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, p)
		}})

	req := httptest.NewRequest("GET", origin.URL+"/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	h.ServeHTTP(httptest.NewRecorder(), req)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("got %d observations, want 1", len(seen))
	}
	if seen[0] != "HTTP/2.0" {
		t.Errorf("observed %q, want HTTP/2.0", seen[0])
	}
}

// The parent-proxy hook has to survive the transport rework, since both live on
// the same transport now.
func TestParentProxyStillAppliesWithExplicitTransports(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	parent := newParentProxy(t, "")
	h := chainedProxy(t, parent.url(), "", nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	proxyURL, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if _, requests, _ := parent.seen(); len(requests) != 1 {
		t.Errorf("the parent saw %d requests, want 1", len(requests))
	}
}
