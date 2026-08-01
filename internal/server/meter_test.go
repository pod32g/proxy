package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// meterRecorder collects what the middleware reports, safely: a hijacked tunnel
// reports from the goroutines pumping it.
type meterRecorder struct {
	mu    sync.Mutex
	total int64
	last  string
}

func (m *meterRecorder) meter(client string, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.total += n
	m.last = client
}

func (m *meterRecorder) read() (int64, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.total, m.last
}

func TestMeterCountsResponseBytes(t *testing.T) {
	var rec meterRecorder
	body := strings.Repeat("x", 4096)
	h := MeterMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}), rec.meter)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:54321"
	h.ServeHTTP(httptest.NewRecorder(), req)

	total, client := rec.read()
	if total != int64(len(body)) {
		t.Errorf("metered %d bytes, want %d", total, len(body))
	}
	// The quota is keyed on a bare address, so the ephemeral port must be gone.
	if client != "10.1.2.3" {
		t.Errorf("client = %q, want the bare address", client)
	}
}

// An upload costs the operator the same as a download, and a quota that counted
// only responses would be sidestepped by a large POST.
func TestMeterCountsRequestBody(t *testing.T) {
	var rec meterRecorder
	body := strings.Repeat("y", 2048)
	h := MeterMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}), rec.meter)

	req := httptest.NewRequest("POST", "http://example.com/", strings.NewReader(body))
	req.RemoteAddr = "10.1.2.3:1"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if total, _ := rec.read(); total != int64(len(body)) {
		t.Errorf("metered %d bytes, want %d", total, len(body))
	}
}

// The case the middleware exists for: once a connection is hijacked nothing
// passes through the ResponseWriter, so a handler-level counter would report
// zero for every CONNECT tunnel and every WebSocket.
func TestMeterCountsHijackedTunnelTraffic(t *testing.T) {
	var rec meterRecorder
	done := make(chan struct{})

	h := MeterMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		// Enough to cross the reporting chunk more than once.
		conn.Write([]byte(strings.Repeat("z", 200<<10)))
		conn.Close()
	}), rec.meter)

	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	io.Copy(io.Discard, conn)
	conn.Close()
	<-done

	// Give the final Close-time flush a moment to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if total, _ := rec.read(); total >= 200<<10 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	total, _ := rec.read()
	t.Errorf("metered %d bytes of tunnel traffic, want at least %d", total, 200<<10)
}

// A long-lived tunnel must not bank its whole cost until it closes, or a
// download that runs for an hour escapes the quota it is supposed to feed.
func TestMeterReportsTunnelTrafficBeforeClose(t *testing.T) {
	var rec meterRecorder
	released := make(chan struct{})
	finished := make(chan struct{})

	h := MeterMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Write([]byte(strings.Repeat("q", meterChunk+1)))
		<-released // still open
		conn.Close()
	}), rec.meter)

	srv := httptest.NewServer(h)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go io.Copy(io.Discard, conn)

	deadline := time.Now().Add(2 * time.Second)
	reported := false
	for time.Now().Before(deadline) {
		if total, _ := rec.read(); total >= meterChunk {
			reported = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(released)
	<-finished
	if !reported {
		t.Error("tunnel traffic was not reported until the connection closed")
	}
}

// The middleware sits outside the metrics recorder, so the interfaces the proxy
// handlers reach for have to survive the extra layer.
func TestMeterPreservesResponseWriterInterfaces(t *testing.T) {
	var rec meterRecorder
	var gotStatus int

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			t.Error("Flusher lost")
		}
		if _, ok := w.(http.Hijacker); !ok {
			t.Error("Hijacker lost")
		}
		s, ok := w.(interface{ SetStatus(int) })
		if !ok {
			t.Fatal("SetStatus lost; a hijacked 101 would be recorded as a 200")
		}
		s.SetStatus(http.StatusSwitchingProtocols)
	})

	// Stand in for the metrics recorder underneath.
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := &statusRecorder{ResponseWriter: w}
		MeterMiddleware(inner, rec.meter).ServeHTTP(r2, r)
		gotStatus = r2.status
	})

	srv := httptest.NewServer(probe)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if gotStatus != http.StatusSwitchingProtocols {
		t.Errorf("status = %d, want the 101 forwarded through the meter", gotStatus)
	}
}

func TestMeterWithoutHookIsAPassthrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	if got := MeterMiddleware(inner, nil); got == nil {
		t.Error("nil meter should return the handler unchanged, not nil")
	}
	if got := MeterMiddleware(nil, func(string, int64) {}); got != nil {
		t.Error("nil handler should stay nil")
	}
}

// Hijack must report what the exchange already cost before the connection is
// taken over, or the request headers and any body read vanish from the count.
func TestMeterFlushesPendingBytesOnHijack(t *testing.T) {
	var rec meterRecorder
	body := strings.Repeat("b", 1024)
	handlerDone := make(chan struct{})

	h := MeterMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		// The pre-hijack body read must already be reported at this point.
		if total, _ := rec.read(); total < int64(len(body)) {
			t.Errorf("metered %d before hijack, want at least %d", total, len(body))
		}
		conn.Close()
	}), rec.meter)

	srv := httptest.NewServer(h)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	w := bufio.NewWriter(conn)
	w.WriteString("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1024\r\n\r\n")
	w.WriteString(body)
	w.Flush()
	<-handlerDone
}
