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
	"sync"
	"testing"
	"time"

	"github.com/pod32g/proxy/internal/header"
	"github.com/pod32g/proxy/internal/reqid"
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

// The identifier has to reach the origin, or the hop it exists to bridge is
// exactly where the trail stops.
func TestRequestIDReachesTheOrigin(t *testing.T) {
	received := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get(reqid.Header)
	}))
	defer backend.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy())
	// Stand in for the middleware that assigns the id in production.
	tagged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(reqid.WithID(r.Context(), "known-id")))
	})
	srv := httptest.NewServer(tagged)
	defer srv.Close()

	resp, err := proxyClient(t, srv.URL).Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	select {
	case got := <-received:
		if got != "known-id" {
			t.Errorf("origin saw %q, want the exchange's id", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin never received the request")
	}
}

// An operator's -header must not be able to displace the identifier, or the
// correlation silently stops working for whoever configured that header.
func TestOperatorHeaderCannotDisplaceTheRequestID(t *testing.T) {
	received := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get(reqid.Header)
	}))
	defer backend.Close()

	h := NewForward(newLogger(), func(string) map[string]string {
		return map[string]string{reqid.Header: "operator-supplied"}
	}, testPolicy())
	tagged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(reqid.WithID(r.Context(), "the-real-id")))
	})
	srv := httptest.NewServer(tagged)
	defer srv.Close()

	resp, err := proxyClient(t, srv.URL).Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	select {
	case got := <-received:
		if got != "the-real-id" {
			t.Errorf("origin saw %q, want the exchange's id to win", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin never received the request")
	}
}

// The tracer is handed the destination with the query already gone. This is the
// seam the "spans carry the destination but not credentials or query strings"
// criterion depends on, so it is asserted here rather than trusted.
func TestTraceHookReceivesASanitisedDestination(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	type call struct{ host, path string }
	calls := make(chan call, 1)
	statuses := make(chan int, 1)

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy(),
		Observer{
			Trace: func(out *http.Request, host, path string) (*http.Request, func(int, error)) {
				calls <- call{host, path}
				// Stand in for traceparent injection.
				out.Header.Set("X-Traceparent-Probe", "injected")
				return out, func(status int, err error) { statuses <- status }
			},
		})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := proxyClient(t, srv.URL).Get(backend.URL + "/search?token=s3cret&q=hi")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	select {
	case c := <-calls:
		if strings.Contains(c.path, "s3cret") || strings.Contains(c.path, "?") {
			t.Errorf("path = %q, want the query dropped before it reaches a span", c.path)
		}
		if c.path != "/search" {
			t.Errorf("path = %q, want %q", c.path, "/search")
		}
		if c.host == "" || strings.Contains(c.host, "@") {
			t.Errorf("host = %q, want a bare authority", c.host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the trace hook was never called")
	}

	select {
	case status := <-statuses:
		if status != http.StatusOK {
			t.Errorf("span ended with status %d, want 200", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the span was never ended")
	}
}

// A span must be ended on the failure paths too, or every refused or failed
// request leaks a span that never closes.
func TestTraceSpanEndsOnRefusal(t *testing.T) {
	ended := make(chan int, 1)
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, Rules: rules(t, "deny all")},
		Observer{
			Trace: func(out *http.Request, host, path string) (*http.Request, func(int, error)) {
				return out, func(status int, err error) { ended <- status }
			},
		})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	h.ServeHTTP(httptest.NewRecorder(), req)

	select {
	case status := <-ended:
		if status != http.StatusForbidden {
			t.Errorf("span ended with %d, want 403", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a refused request left its span open")
	}
}

// "Entirely optional with no cost when disabled": with no hook the handler must
// do no tracing work at all, not call into a no-op.
func BenchmarkObserverTraceDisabled(b *testing.B) {
	var obs Observer
	req := httptest.NewRequest("GET", "http://example.com/a", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, end := obs.trace(req, "example.com", "/a")
		_ = out
		end(200, nil)
	}
}

// servedRecorder stands in for the accounting layer, which is the only thing
// that consumes this signal in production.
type servedRecorder struct {
	http.ResponseWriter
	served bool
}

func (s *servedRecorder) SetServed() { s.served = true }

func (s *servedRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := s.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// A request the proxy refused never reached a destination, so it must not be
// counted as traffic to the host it was refused from. The status alone cannot
// carry this: an origin can answer 403 exactly as a policy refusal does.
func TestRefusedRequestsAreNotMarkedServed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pol    Policy
		method string
		target string
	}{
		{"destination rule", Policy{AllowPrivate: true, Rules: rules(t, "deny all")},
			http.MethodGet, "http://example.com/"},
		{"private address default", Policy{}, http.MethodGet, "http://127.0.0.1:9/"},
		{"connect port", Policy{AllowPrivate: true}, http.MethodConnect, "example.com:25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewForward(newLogger(), func(string) map[string]string { return nil }, tc.pol)
			req := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.method == http.MethodConnect {
				req.Host = tc.target
			}
			req.RemoteAddr = "10.1.2.3:5000"

			rec := &servedRecorder{ResponseWriter: httptest.NewRecorder()}
			h.ServeHTTP(rec, req)

			if rec.served {
				t.Error("a refused request was marked as having reached a destination")
			}
		})
	}
}

// And a request that did reach an origin must be marked, whatever the origin
// answered — a 403 from the origin is still a destination the proxy served.
func TestServedIsMarkedEvenWhenTheOriginRefuses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer backend.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy())
	u, _ := url.Parse(backend.URL)
	req := httptest.NewRequest(http.MethodGet, backend.URL+"/x", nil)
	req.URL = u.JoinPath("/x")
	req.RemoteAddr = "10.1.2.3:5000"

	rec := &servedRecorder{ResponseWriter: httptest.NewRecorder()}
	h.ServeHTTP(rec, req)

	if !rec.served {
		t.Error("an origin's own 403 was mistaken for a refusal we made")
	}
}

// A CONNECT tunnel reaches its destination at the dial, before any byte flows.
func TestConnectMarksServedOnceTheTunnelIsUp(t *testing.T) {
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
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	portNum := 0
	fmt.Sscanf(port, "%d", &portNum)

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: []int{portNum}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &servedRecorder{ResponseWriter: w}
		h.ServeHTTP(rec, r)
		if !rec.served {
			t.Error("an established tunnel was not marked as served")
		}
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
	head := make([]byte, 0, 128)
	buf := make([]byte, 1)
	for !hasHeaderEnd(head) {
		if _, err := conn.Read(buf); err != nil {
			break
		}
		head = append(head, buf[0])
	}
}

// Header rules end to end, through the real handler rather than the rule
// engine alone: the engine passing says nothing about whether anything calls it.
func TestHeaderRulesApplyEndToEnd(t *testing.T) {
	received := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.Header().Set("X-Backend", "original")
		w.Header().Set("X-Strip-Me", "still here")
	}))
	defer backend.Close()

	rules, err := header.Parse(strings.Join([]string{
		"set X-Added: yes",
		"remove X-Client-Sent",
		"replace User-Agent: proxied",
		"response set X-Backend: rewritten",
		"response remove X-Strip-Me",
	}, "\n"))
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(),
			HeaderRules: func(string) *header.RuleSet { return rules },
		})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", backend.URL+"/", nil)
	req.Header.Set("X-Client-Sent", "please remove me")
	req.Header.Set("User-Agent", "curl/8")
	resp, err := proxyClient(t, srv.URL).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	select {
	case got := <-received:
		if got.Get("X-Added") != "yes" {
			t.Error("set did not reach the origin")
		}
		if got.Get("X-Client-Sent") != "" {
			t.Error("remove did not reach the origin")
		}
		if got.Get("User-Agent") != "proxied" {
			t.Errorf("replace: User-Agent = %q", got.Get("User-Agent"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin never received the request")
	}

	if resp.Header.Get("X-Backend") != "rewritten" {
		t.Errorf("response set: X-Backend = %q", resp.Header.Get("X-Backend"))
	}
	if resp.Header.Get("X-Strip-Me") != "" {
		t.Error("response remove did not take effect")
	}
}

// The guard has to hold through the whole path, not just at parse time: a
// client's Proxy-Authorization must never reach an origin, and no configuration
// may cause it to.
func TestHeaderRulesCannotLeakProxyCredentials(t *testing.T) {
	received := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
	}))
	defer backend.Close()

	// Every attempt to express this is rejected when written, so the rule set
	// reaching the handler cannot contain one.
	for _, attempt := range []string{
		"set Proxy-Authorization: Basic YWRtaW46aHVudGVyMg==",
		"set Connection: X-Secret",
		"response set Proxy-Authenticate: Basic",
	} {
		if _, err := header.Parse(attempt); err == nil {
			t.Fatalf("the parser accepted %q, so the guard can be bypassed by configuration", attempt)
		}
	}

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts(),
			HeaderRules: func(string) *header.RuleSet { return &header.RuleSet{} }})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", backend.URL+"/", nil)
	req.Header.Set("Proxy-Authorization", "Basic YWRtaW46aHVudGVyMg==")
	resp, err := proxyClient(t, srv.URL).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	select {
	case got := <-received:
		if got.Get("Proxy-Authorization") != "" {
			t.Error("the client's proxy credentials reached the origin")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin never received the request")
	}
}
