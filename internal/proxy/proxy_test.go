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
	"time"

	"github.com/pod32g/proxy/internal/policy"
	log "github.com/pod32g/simple-logger"
)

func newLogger() *log.Logger {
	l, err := log.New(log.WithOutput(io.Discard), log.WithLevel(log.ERROR))
	if err != nil {
		panic(err)
	}
	return l
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
	rp := New(u, newLogger(), func(string) map[string]string { return headers }, Policy{})
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
	rp := New(u, newLogger(), func(string) map[string]string { return nil }, Policy{})
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

	fp := NewForward(newLogger(), func(string) map[string]string { return map[string]string{"X-Test": "value"} }, testPolicy())
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

	fp := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy())
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
	fp := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy())
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

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy())

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
	}, testPolicy())
	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.RequestURI = ""
	req.Header.Set("X-Override", "from-client")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.Get("X-Proxy-Name") != "edge" || got.Get("X-Override") != "from-proxy" {
		t.Fatalf("configured headers not applied: %v", got)
	}
}

// Tests dial loopback listeners on arbitrary ports, which the shipping default
// deliberately refuses. Policy behaviour has its own tests below.
func testPolicy() Policy {
	return Policy{AllowPrivate: true, ConnectPorts: allPorts()}
}

func allPorts() []int {
	out := make([]int, 0, 65535)
	for i := 1; i <= 65535; i++ {
		out = append(out, i)
	}
	return out
}

// A forward proxy takes destinations from untrusted clients, so the default
// must not let them reach the proxy host's own network.
func TestPolicyBlocksPrivateDestinations(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SECRET"))
	}))
	defer internal.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, Policy{})
	req := httptest.NewRequest(http.MethodGet, internal.URL+"/", nil)
	req.RequestURI = ""
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d %q, want 403", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SECRET") {
		t.Fatal("internal response body reached the client")
	}
}

func TestPolicyAllowPrivateOptsBackIn(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SECRET"))
	}))
	defer internal.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true})
	req := httptest.NewRequest(http.MethodGet, internal.URL+"/", nil)
	req.RequestURI = ""
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "SECRET") {
		t.Fatalf("opt-in did not take effect: %d %q", rec.Code, rec.Body.String())
	}
}

// An unrestricted CONNECT is a general-purpose TCP relay, so the port list is
// enforced before anything is dialled.
func TestPolicyRestrictsConnectPorts(t *testing.T) {
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true}) // default port list: 443 only

	for _, tc := range []struct {
		target string
		want   int
	}{
		{"127.0.0.1:25", http.StatusForbidden},
		{"127.0.0.1:22", http.StatusForbidden},
		{"127.0.0.1:6379", http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodConnect, "http://"+tc.target, nil)
		req.Host = tc.target
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("CONNECT %s: got %d, want %d", tc.target, rec.Code, tc.want)
		}
	}
}

// Per-client header rules are configured against an address an operator can
// read off the UI, which never carries the ephemeral source port.
func TestClientHeadersKeyedByIP(t *testing.T) {
	var got http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer origin.Close()

	lookups := []string{}
	h := NewForward(newLogger(), func(client string) map[string]string {
		lookups = append(lookups, client)
		if client == "192.0.2.10" {
			return map[string]string{"X-Team": "blue"}
		}
		return nil
	}, testPolicy())

	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.RequestURI = ""
	req.RemoteAddr = "192.0.2.10:54321"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.Get("X-Team") != "blue" {
		t.Fatalf("client header not applied; lookups were %v", lookups)
	}
}

func TestClientIPStripsPort(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.10:54321", "192.0.2.10"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"192.0.2.10", "192.0.2.10"},
		{"", ""},
	} {
		if got := clientIP(tc.in); got != tc.want {
			t.Errorf("clientIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The destination policy must apply to CONNECT as well as plain HTTP — an
// allowed port to a loopback address is still a pivot into the proxy host.
func TestPolicyBlocksPrivateConnectDestination(t *testing.T) {
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{ConnectPorts: []int{9111}}) // port allowed, address not
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Written in one shot and the connection held open: closing the write side
	// would cancel the request context and abort the dial before the policy
	// check could report anything.
	fmt.Fprint(conn, "CONNECT 127.0.0.1:9111 HTTP/1.1\r\nHost: 127.0.0.1:9111\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	if !strings.Contains(line, "403") {
		t.Fatalf("got %q, want 403 for a loopback CONNECT target", strings.TrimSpace(line))
	}
}

// A ws:// request through forward mode must complete its handshake and pass
// data. Upgrade is hop-by-hop, so before this the strip removed the handshake
// and the client got an ordinary response instead of a protocol switch.
func TestForwardProxiesUpgrade(t *testing.T) {
	// Origin that accepts the upgrade and then echoes, uppercased, so the test
	// can tell real bidirectional traffic from a replayed buffer.
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		c, err := origin.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		var sawUpgrade, sawKey bool
		for {
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "upgrade:") && strings.Contains(lower, "websocket") {
				sawUpgrade = true
			}
			if strings.HasPrefix(lower, "sec-websocket-key:") {
				sawKey = true
			}
		}
		if !sawUpgrade || !sawKey {
			io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			return
		}
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: test-accept-value\r\n\r\n")
		for {
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return
			}
			io.WriteString(c, strings.ToUpper(line))
		}
	}()

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy())
	proxySrv := httptest.NewServer(h)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET http://%s/chat HTTP/1.1\r\nHost: %s\r\n"+
		"Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		origin.Addr(), origin.Addr())

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake not proxied: %q", strings.TrimSpace(status))
	}
	// The origin's negotiated headers must reach the client, or no real
	// WebSocket client would accept the connection.
	var sawAccept bool
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.Contains(strings.ToLower(line), "sec-websocket-accept: test-accept-value") {
			sawAccept = true
		}
	}
	if !sawAccept {
		t.Error("origin's Sec-WebSocket-Accept did not reach the client")
	}

	// Traffic after the switch must flow in both directions.
	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		t.Fatalf("write after upgrade: %v", err)
	}
	echoed, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read after upgrade: %v", err)
	}
	if strings.TrimSpace(echoed) != "HELLO" {
		t.Fatalf("got %q, want %q", strings.TrimSpace(echoed), "HELLO")
	}
}

// An origin that declines the upgrade gets relayed as an ordinary response
// rather than hijacked.
func TestForwardUpgradeDeclinedByOrigin(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no upgrades here", http.StatusUpgradeRequired)
	}))
	defer origin.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy())
	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.RequestURI = ""
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("got %d, want the origin's %d", rec.Code, http.StatusUpgradeRequired)
	}
	if !strings.Contains(rec.Body.String(), "no upgrades here") {
		t.Errorf("origin body lost: %q", rec.Body.String())
	}
}

func TestRequestedUpgrade(t *testing.T) {
	for _, tc := range []struct{ conn, upgrade, want string }{
		{"Upgrade", "websocket", "websocket"},
		{"keep-alive, Upgrade", "websocket", "websocket"}, // Connection is a list
		{"upgrade", "h2c", "h2c"},                         // token match is case-insensitive
		{"keep-alive", "websocket", ""},                   // not requested
		{"", "websocket", ""},                             // Upgrade alone is not enough
		{"Upgrade", "", ""},
	} {
		h := http.Header{}
		if tc.conn != "" {
			h.Set("Connection", tc.conn)
		}
		if tc.upgrade != "" {
			h.Set("Upgrade", tc.upgrade)
		}
		if got := requestedUpgrade(h); got != tc.want {
			t.Errorf("Connection=%q Upgrade=%q: got %q, want %q", tc.conn, tc.upgrade, got, tc.want)
		}
	}
}

// Ordinary requests must keep stripping hop-by-hop headers exactly as before.
func TestNonUpgradeRequestsStillStripped(t *testing.T) {
	var got http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer origin.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, testPolicy())
	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.RequestURI = ""
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade", "websocket") // present but not requested via Connection
	req.Header.Set("Proxy-Authorization", "Basic x")
	h.ServeHTTP(httptest.NewRecorder(), req)

	for _, name := range []string{"Connection", "Upgrade", "Proxy-Authorization"} {
		if v := got.Get(name); v != "" {
			t.Errorf("origin saw hop-by-hop header %s: %q", name, v)
		}
	}
}

func rules(t *testing.T, text string) func(string) *policy.RuleSet {
	t.Helper()
	set, err := policy.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return func(string) *policy.RuleSet { return set }
}

// The ordered list must be honoured end to end, including the case that
// motivates evaluating post-DNS: a CIDR allow ahead of a deny-all, for a
// hostname that resolves into the allowed range.
func TestPolicyRulesEndToEnd(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("REACHED"))
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	for _, tc := range []struct {
		name, ruleText string
		wantCode       int
	}{
		{"deny all blocks everything", "deny all", http.StatusForbidden},
		{"allow all permits", "allow all", http.StatusOK},
		{"cidr allow ahead of deny all", "allow cidr " + originHost + "/32\ndeny all", http.StatusOK},
		{"deny all with an unrelated cidr allow", "allow cidr 198.51.100.0/24\ndeny all", http.StatusForbidden},
		{"specific deny precedes broad allow", "deny cidr " + originHost + "/32\nallow all", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewForward(newLogger(), func(string) map[string]string { return nil },
				Policy{AllowPrivate: true, Rules: rules(t, tc.ruleText)})
			req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
			req.RequestURI = ""
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("got %d (%q), want %d", rec.Code, strings.TrimSpace(rec.Body.String()), tc.wantCode)
			}
		})
	}
}

// An explicit allow is a deliberate act and overrides the private-address
// default, so an internal range can be opened without -allow-private.
func TestPolicyAllowOverridesPrivateDefault(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("REACHED"))
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{Rules: rules(t, "allow cidr "+originHost+"/32")}) // AllowPrivate stays false
	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.RequestURI = ""
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d (%q), want 200", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

// A tunnel must not reach anywhere an ordinary request could not.
func TestPolicyRulesApplyToConnect(t *testing.T) {
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts(), Rules: rules(t, "deny all")})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", svc.Addr(), svc.Addr())
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "403") {
		t.Fatalf("got %q, want 403", strings.TrimSpace(line))
	}
}

// With no rules configured nothing changes: the private-address default is
// still the only constraint.
func TestNoRulesLeavesBehaviourUnchanged(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	strict := NewForward(newLogger(), func(string) map[string]string { return nil }, Policy{})
	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.RequestURI = ""
	rec := httptest.NewRecorder()
	strict.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("loopback should still be refused: got %d", rec.Code)
	}
}

// Per-client destination rules must reach the dialer, which is the only place
// the resolved address is known.
func TestPerClientDestinationRules(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("REACHED"))
	}))
	defer origin.Close()

	permissive, err := policy.Parse("allow all")
	if err != nil {
		t.Fatal(err)
	}
	restrictive, err := policy.Parse("deny all")
	if err != nil {
		t.Fatal(err)
	}

	h := NewForward(newLogger(), func(string) map[string]string { return nil }, Policy{
		AllowPrivate: true,
		Rules: func(client string) *policy.RuleSet {
			if client == "203.0.113.9" {
				return restrictive
			}
			return permissive
		},
	})

	for _, tc := range []struct {
		client   string
		wantCode int
	}{
		{"203.0.113.9", http.StatusForbidden},
		{"10.0.0.5", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
		req.RequestURI = ""
		req.RemoteAddr = tc.client + ":40000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode {
			t.Errorf("client %s: got %d, want %d", tc.client, rec.Code, tc.wantCode)
		}
	}
}
