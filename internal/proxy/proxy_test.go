package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	log "github.com/pod32g/simple-logger"
)

func newLogger() *log.Logger {
	return log.NewLogger(io.Discard, log.ERROR, &log.DefaultFormatter{})
}

func TestNewAddsHeader(t *testing.T) {
	var received string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("X-Forwarded-By")
	}))
	defer backend.Close()

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	rp := New(u, newLogger())
	proxySrv := httptest.NewServer(rp)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	resp.Body.Close()

	if received != "MyGoProxy" {
		t.Fatalf("expected header 'MyGoProxy', got %q", received)
	}
}

func TestErrorHandlerReturnsBadGateway(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	rp := New(u, newLogger())
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
