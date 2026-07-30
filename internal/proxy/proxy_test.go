package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	log "github.com/pod32g/simple-logger"
)

func newLogger() *log.Logger {
	return log.NewLogger(io.Discard, log.ERROR, &log.DefaultFormatter{})
}

func TestNewAddsHeader(t *testing.T) {
	var received string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("X-Test")
	}))
	defer backend.Close()

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	headers := map[string]string{"X-Test": "value"}
	rp := New(u, newLogger(), func(string) map[string]string { return headers })
	proxySrv := httptest.NewServer(rp)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	resp.Body.Close()

	if received != "value" {
		t.Fatalf("expected header 'value', got %q", received)
	}
}

func TestErrorHandlerReturnsBadGateway(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	rp := New(u, newLogger(), func(string) map[string]string { return nil })
	proxySrv := httptest.NewServer(rp)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 status, got %d", resp.StatusCode)
	}
}

func TestForwardAddsHeader(t *testing.T) {
	var received string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("X-Test")
	}))
	defer backend.Close()

	fp := NewForward(newLogger(), func(string) map[string]string { return map[string]string{"X-Test": "value"} })
	proxySrv := httptest.NewServer(fp)
	defer proxySrv.Close()

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	resp.Body.Close()

	if received != "value" {
		t.Fatalf("expected header 'value', got %q", received)
	}
}

func TestForwardConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			io.Copy(io.Discard, conn)
			conn.Close()
		}
		close(done)
	}()

	fp := NewForward(newLogger(), func(string) map[string]string { return nil })
	proxySrv := httptest.NewServer(fp)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	host := ln.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("expected 200 response, got %q", line)
	}
	conn.Close()
	<-done
}

func TestForwardInvalidRequest(t *testing.T) {
	fp := NewForward(newLogger(), func(string) map[string]string { return nil })
	proxySrv := httptest.NewServer(fp)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/favicon.ico")
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 status, got %d", resp.StatusCode)
	}
}

// Credentials the client used to authenticate to the proxy must not be handed
// to the origin, along with the rest of the per-hop header set (RFC 7230 §6.1).
func TestForwardStripsHopByHopHeaders(t *testing.T) {
	var got http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"upstream\"")
		w.Header().Set("Connection", "X-Upstream-Hop")
		w.Header().Set("X-Upstream-Hop", "should-not-reach-client")
		w.Header().Set("X-Keep", "kept")
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil })

	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.RequestURI = ""
	req.Header.Set("Proxy-Authorization", "Basic YWxpY2U6czNjcmV0")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Te", "trailers")
	// A sender may name additional per-hop headers in Connection.
	req.Header.Set("Connection", "X-Client-Hop, X-Other-Hop")
	req.Header.Set("X-Client-Hop", "should-not-reach-origin")
	req.Header.Set("X-Other-Hop", "should-not-reach-origin")
	req.Header.Set("X-End-To-End", "should-reach-origin")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, name := range []string{
		"Proxy-Authorization", "Proxy-Connection", "Keep-Alive", "Te",
		"Connection", "X-Client-Hop", "X-Other-Hop",
	} {
		if v := got.Get(name); v != "" {
			t.Errorf("origin saw hop-by-hop header %s: %q", name, v)
		}
	}
	if v := got.Get("X-End-To-End"); v != "should-reach-origin" {
		t.Errorf("end-to-end header lost: %q", v)
	}

	resp := rec.Result()
	for _, name := range []string{"Proxy-Authenticate", "Connection", "X-Upstream-Hop"} {
		if v := resp.Header.Get(name); v != "" {
			t.Errorf("client saw hop-by-hop response header %s: %q", name, v)
		}
	}
	if v := resp.Header.Get("X-Keep"); v != "kept" {
		t.Errorf("end-to-end response header lost: %q", v)
	}
}

// Configured headers are still applied, and win over anything the client sent.
func TestForwardStillAppliesConfiguredHeaders(t *testing.T) {
	var got http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer origin.Close()

	h := NewForward(newLogger(), func(string) map[string]string {
		return map[string]string{"X-Proxy-Name": "edge", "X-Override": "from-proxy"}
	})
	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.RequestURI = ""
	req.Header.Set("X-Override", "from-client")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.Get("X-Proxy-Name") != "edge" || got.Get("X-Override") != "from-proxy" {
		t.Fatalf("configured headers not applied: %v", got)
	}
}
