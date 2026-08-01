package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// recorder collects observations from every goroutine that makes one — a tunnel
// closes on a pump goroutine, not the handler's.
type recorder struct {
	mu       sync.Mutex
	upstream []time.Duration
	methods  []string
	denials  []string
	open     int
	maxOpen  int
}

func (r *recorder) observer() Observer {
	return Observer{
		Upstream: func(method string, d time.Duration) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.upstream = append(r.upstream, d)
			r.methods = append(r.methods, method)
		},
		Denied: func(scope string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.denials = append(r.denials, scope)
		},
		TunnelOpened: func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.open++
			if r.open > r.maxOpen {
				r.maxOpen = r.open
			}
		},
		TunnelClosed: func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.open--
		},
	}
}

func (r *recorder) snapshot() ([]time.Duration, []string, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.upstream...),
		append([]string(nil), r.denials...), r.open, r.maxOpen
}

// The whole reason upstream timing is separate: the total duration cannot tell
// a slow origin from a slow proxy.
func TestObserverTimesTheUpstreamOnly(t *testing.T) {
	const originDelay = 60 * time.Millisecond
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(originDelay)
	}))
	defer backend.Close()

	var rec recorder
	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy(), rec.observer())
	srv := httptest.NewServer(h)
	defer srv.Close()

	client := proxyClient(t, srv.URL)
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	up, _, _, _ := rec.snapshot()
	if len(up) != 1 {
		t.Fatalf("got %d upstream observations, want 1", len(up))
	}
	if up[0] < originDelay {
		t.Errorf("upstream = %v, want at least the origin's %v", up[0], originDelay)
	}
	// Generous, but it must not have swallowed anything wildly unrelated.
	if up[0] > originDelay*10 {
		t.Errorf("upstream = %v, implausibly more than the origin's %v", up[0], originDelay)
	}
	if rec.methods[0] != http.MethodGet {
		t.Errorf("method = %q, want GET", rec.methods[0])
	}
}

// Refusals are attributed by which check made them, so a spike is diagnosable
// from the metric alone rather than by reading logs.
func TestObserverAttributesRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pol    Policy
		method string
		target string
		want   string
	}{
		{
			name:   "destination rule",
			pol:    Policy{AllowPrivate: true, Rules: rules(t, "deny all")},
			method: http.MethodGet,
			target: "http://example.com/",
			want:   scopeDestination,
		},
		{
			name:   "private address default",
			pol:    Policy{},
			method: http.MethodGet,
			target: "http://127.0.0.1:9/",
			want:   scopePrivateAddr,
		},
		{
			name:   "connect port",
			pol:    Policy{AllowPrivate: true},
			method: http.MethodConnect,
			target: "example.com:25",
			want:   scopeConnectPort,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec recorder
			h := NewForward(newLogger(), func(string) map[string]string { return nil }, tc.pol, rec.observer())

			req := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.method == http.MethodConnect {
				req.Host = tc.target
			}
			req.RemoteAddr = "10.1.2.3:5000"
			h.ServeHTTP(httptest.NewRecorder(), req)

			_, denials, _, _ := rec.snapshot()
			if len(denials) != 1 {
				t.Fatalf("got %d denials, want 1: %v", len(denials), denials)
			}
			if denials[0] != tc.want {
				t.Errorf("scope = %q, want %q", denials[0], tc.want)
			}
		})
	}
}

// A CONNECT tunnel is one request but arbitrary traffic for an unbounded time,
// so a request counter sees it exactly once and a gauge is the only honest view.
func TestObserverTracksLiveTunnels(t *testing.T) {
	// A TCP echo the tunnel can reach, so the tunnel genuinely establishes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	portNum := 0
	fmt.Sscanf(port, "%d", &portNum)

	var rec recorder
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: []int{portNum}}, rec.observer())
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
	head := make([]byte, 0, 128)
	buf := make([]byte, 1)
	for !hasHeaderEnd(head) {
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		head = append(head, buf[0])
	}

	// The tunnel is established and must be counted while it is open.
	if !eventually(t, func() bool { _, _, open, _ := rec.snapshot(); return open == 1 }) {
		_, _, open, _ := rec.snapshot()
		t.Fatalf("open tunnels = %d while one is established, want 1", open)
	}

	conn.Close()

	// And must come back down when it closes, or the gauge only ever climbs.
	if !eventually(t, func() bool { _, _, open, _ := rec.snapshot(); return open == 0 }) {
		_, _, open, _ := rec.snapshot()
		t.Errorf("open tunnels = %d after close, want 0", open)
	}
	if _, _, _, maxOpen := rec.snapshot(); maxOpen != 1 {
		t.Errorf("peak tunnels = %d, want 1", maxOpen)
	}
}

// The zero Observer must be safe: it is what every call site that does not
// measure anything passes.
func TestZeroObserverIsSafe(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy(), Observer{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	client := proxyClient(t, srv.URL)
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
}

func hasHeaderEnd(b []byte) bool {
	return len(b) >= 4 && string(b[len(b)-4:]) == "\r\n\r\n"
}

func eventually(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// proxyClient returns a client that sends everything through the proxy under
// test.
func proxyClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatalf("proxy url: %v", err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}
