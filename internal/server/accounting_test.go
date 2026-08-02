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
	mu      sync.Mutex
	total   int64
	in, out int64
	last    string
}

func (m *meterRecorder) meter(client string, in, out int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.total += in + out
	m.in += in
	m.out += out
	m.last = client
}

func (m *meterRecorder) read() (int64, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.total, m.last
}

// directions returns the split, which the metrics consumer needs and the quota
// does not.
func (m *meterRecorder) directions() (int64, int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.in, m.out
}

func TestAccountingCountsResponseBytes(t *testing.T) {
	var rec meterRecorder
	body := strings.Repeat("x", 4096)
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}), Accounting{Charge: rec.meter})

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
func TestAccountingCountsRequestBody(t *testing.T) {
	var rec meterRecorder
	body := strings.Repeat("y", 2048)
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}), Accounting{Charge: rec.meter})

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
func TestAccountingCountsHijackedTunnelTraffic(t *testing.T) {
	var rec meterRecorder
	done := make(chan struct{})

	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		// Enough to cross the reporting chunk more than once.
		conn.Write([]byte(strings.Repeat("z", 200<<10)))
		conn.Close()
	}), Accounting{Charge: rec.meter})

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
func TestAccountingReportsTunnelTrafficBeforeClose(t *testing.T) {
	var rec meterRecorder
	released := make(chan struct{})
	finished := make(chan struct{})

	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Write([]byte(strings.Repeat("q", chargeChunk+1)))
		<-released // still open
		conn.Close()
	}), Accounting{Charge: rec.meter})

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
		if total, _ := rec.read(); total >= chargeChunk {
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
func TestAccountingPreservesResponseWriterInterfaces(t *testing.T) {
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
		AccountingMiddleware(inner, Accounting{Charge: rec.meter}).ServeHTTP(r2, r)
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

func TestAccountingWithoutHooksIsAPassthrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	if got := AccountingMiddleware(inner, Accounting{}); got == nil {
		t.Error("no hooks should return the handler unchanged, not nil")
	}
	if got := AccountingMiddleware(nil, Accounting{Charge: func(string, int64, int64) {}}); got != nil {
		t.Error("nil handler should stay nil")
	}
}

// Hijack must report what the exchange already cost before the connection is
// taken over, or the request headers and any body read vanish from the count.
func TestAccountingFlushesPendingBytesOnHijack(t *testing.T) {
	var rec meterRecorder
	body := strings.Repeat("b", 1024)
	handlerDone := make(chan struct{})

	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}), Accounting{Charge: rec.meter})

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

// PROXY-88. The request identifier is capped at 128 with an explicit note about
// bloating every log line. Host and Path are on the same line, from the same
// client, and were capped by nothing.
func TestClientControlledLogFieldsAreBounded(t *testing.T) {
	long := strings.Repeat("a", 8000)
	for _, tc := range []struct {
		name   string
		target string
		method string
	}{
		{"absolute-form host and path", "http://" + long + ".example.com/" + long, http.MethodGet},
		{"CONNECT authority", "http://x/", http.MethodConnect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got Exchange
			h := AccountingMiddleware(okHandler("ok"), Accounting{
				Completed: func(e Exchange) { got = e },
			})
			req := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.method == http.MethodConnect {
				req.Host = long + ".example.com:443"
			}
			req.RemoteAddr = "10.1.2.3:5000"
			req.Header.Set("X-Request-Id", strings.Repeat("z", 8000))
			h.ServeHTTP(httptest.NewRecorder(), req)

			for _, f := range []struct {
				name  string
				value string
			}{{"host", got.Host}, {"path", got.Path}, {"request id", got.RequestID}} {
				if len(f.value) > MaxLoggedField+len("…[truncated]") {
					t.Errorf("%s is %d chars; nothing bounds it", f.name, len(f.value))
				}
			}
			// Truncation must be visible, or a reader sees a different URL than
			// was requested and has no way to know.
			if len(got.Host) > MaxLoggedField && !strings.HasSuffix(got.Host, "[truncated]") {
				t.Errorf("host was cut without a marker: %q", got.Host[len(got.Host)-20:])
			}
		})
	}
}
