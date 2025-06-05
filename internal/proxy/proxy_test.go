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
	rp := New(u, newLogger(), func() map[string]string { return headers })
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
	rp := New(u, newLogger(), func() map[string]string { return nil })
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

	fp := NewForward(newLogger(), func() map[string]string { return map[string]string{"X-Test": "value"} })
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

	fp := NewForward(newLogger(), func() map[string]string { return nil })
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
	fp := NewForward(newLogger(), func() map[string]string { return nil })
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
