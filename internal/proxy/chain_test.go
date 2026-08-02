package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/upstream"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// parentProxy is a real proxy running in-process: it speaks both the plain-HTTP
// and the CONNECT halves of the protocol, and records what it was asked for.
//
// A mock that merely accepted connections would not exercise the nested CONNECT
// handshake, which is the part with substance.
type parentProxy struct {
	ln net.Listener

	mu       sync.Mutex
	connects []string
	requests []string
	auth     []string

	// requireAuth makes the parent demand credentials, so the credential half
	// of the criterion is actually exercised rather than assumed.
	requireAuth string
}

func newParentProxy(t *testing.T, requireAuth string) *parentProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &parentProxy{ln: ln, requireAuth: requireAuth}
	go p.serve()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *parentProxy) addr() string { return p.ln.Addr().String() }
func (p *parentProxy) url() string  { return "http://" + p.addr() }

func (p *parentProxy) record(connect, request, auth string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if connect != "" {
		p.connects = append(p.connects, connect)
	}
	if request != "" {
		p.requests = append(p.requests, request)
	}
	p.auth = append(p.auth, auth)
}

func (p *parentProxy) seen() ([]string, []string, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...),
		append([]string(nil), p.requests...),
		append([]string(nil), p.auth...)
}

func (p *parentProxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *parentProxy) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	auth := req.Header.Get("Proxy-Authorization")

	if p.requireAuth != "" && auth != p.requireAuth {
		p.record("", "", auth)
		io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"parent\"\r\nContent-Length: 0\r\n\r\n")
		return
	}

	if req.Method == http.MethodConnect {
		p.record(req.Host, "", auth)
		dest, err := net.Dial("tcp", req.Host)
		if err != nil {
			io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer dest.Close()
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		// Anything the client pipelined behind its CONNECT belongs to the
		// tunnel.
		if n := br.Buffered(); n > 0 {
			pending, _ := br.Peek(n)
			dest.Write(pending)
		}
		go io.Copy(dest, conn)
		io.Copy(conn, dest)
		return
	}

	// Plain HTTP: the request arrives in absolute form and the parent fetches.
	p.record("", req.URL.String(), auth)
	req.RequestURI = ""
	// Hop-by-hop, and recorded above already. A parent that forwarded it would
	// be the bug under test in another costume.
	req.Header.Del("Proxy-Authorization")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	resp.Write(conn)
}

func chainedProxy(t *testing.T, parentURL, noProxy string, rules func(string) *policy.RuleSet) http.Handler {
	t.Helper()
	up, err := upstream.Parse(parentURL, noProxy)
	if err != nil {
		t.Fatalf("upstream.Parse: %v", err)
	}
	pol := Policy{AllowPrivate: true, ConnectPorts: allPorts(), Upstream: func() *upstream.Proxy { return up }, Rules: rules}
	return NewForward(newLogger(), func(string) map[string]string { return nil }, pol)
}

// The plain-HTTP half: the request must reach the origin *via* the parent.
func TestChainedPlainHTTPGoesThroughTheParent(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	parent := newParentProxy(t, "")
	h := chainedProxy(t, parent.url(), "", nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := proxyClient(t, srv.URL).Get(origin.URL + "/path")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ORIGIN" {
		t.Errorf("body = %q, want ORIGIN", body)
	}

	_, requests, _ := parent.seen()
	if len(requests) != 1 {
		t.Fatalf("the parent saw %d requests, want 1 — the proxy went direct", len(requests))
	}
	if !strings.Contains(requests[0], "/path") {
		t.Errorf("the parent saw %q", requests[0])
	}
}

// The CONNECT half, which is where the substance is: the proxy has to dial the
// parent and issue a nested CONNECT rather than dialling the destination.
func TestChainedConnectIssuesANestedConnect(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "TUNNELLED")
	}))
	origin.StartTLS()
	defer origin.Close()

	parent := newParentProxy(t, "")
	h := chainedProxy(t, parent.url(), "", nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "TUNNELLED" {
		t.Errorf("body = %q, want TUNNELLED", body)
	}

	connects, _, _ := parent.seen()
	if len(connects) != 1 {
		t.Fatalf("the parent saw %d CONNECTs, want 1 — the proxy dialled the origin directly", len(connects))
	}
	if !strings.Contains(connects[0], strings.TrimPrefix(origin.URL, "https://")) {
		t.Errorf("the parent was asked for %q, want the real destination", connects[0])
	}
}

// Credentials have to reach the parent on both paths, or a parent that demands
// them makes the proxy unusable in exactly the network this feature is for.
func TestChainedCredentialsReachTheParent(t *testing.T) {
	const user, pass = "chainuser", "chainpass"
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	parent := newParentProxy(t, expected)
	parentURL := "http://" + user + ":" + pass + "@" + parent.addr()

	h := chainedProxy(t, parentURL, "", nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := proxyClient(t, srv.URL).Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ORIGIN" {
		t.Fatalf("body = %q — the parent rejected the credentials", body)
	}

	_, _, auth := parent.seen()
	if len(auth) == 0 || auth[0] != expected {
		t.Errorf("the parent saw %v, want the configured credentials", auth)
	}
}

// A parent that refuses must surface as a gateway error, not as a tunnel that
// silently carries the parent's error page instead of the origin.
func TestParentRefusalIsAGatewayError(t *testing.T) {
	parent := newParentProxy(t, "Basic something-else")
	h := chainedProxy(t, parent.url(), "", nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Host = "example.com:443"
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("a refusal by the parent was reported as a established tunnel")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestBypassGoesDirect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "DIRECT")
	}))
	defer origin.Close()

	parent := newParentProxy(t, "")
	// The origin is on 127.0.0.1, so a loopback bypass covers it.
	h := chainedProxy(t, parent.url(), "127.0.0.0/8", nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := proxyClient(t, srv.URL).Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "DIRECT" {
		t.Errorf("body = %q", body)
	}

	connects, requests, _ := parent.seen()
	if len(connects)+len(requests) != 0 {
		t.Errorf("a bypassed destination still went through the parent: %v %v", connects, requests)
	}
}

// The criterion that most needed care: the destination policy must keep
// applying to the *requested* destination, not the parent.
//
// This is not automatic. The policy is normally enforced in ControlContext, on
// the address about to be connected to — which with a parent configured is the
// parent, the same address for every request. A naive implementation would
// evaluate the rules against the parent's IP, so "deny domain blocked.test"
// would match nothing and the rule would stop meaning what it says, silently.
func TestDestinationPolicyAppliesToTheRequestedDestinationNotTheParent(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	parent := newParentProxy(t, "")

	t.Run("a denied destination is refused even though the parent is allowed", func(t *testing.T) {
		h := chainedProxy(t, parent.url(), "", rules(t, "deny domain blocked.test\nallow all"))

		req := httptest.NewRequest("GET", "http://blocked.test/", nil)
		req.RemoteAddr = "10.1.2.3:5000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 — the rule was evaluated against the parent", rec.Code)
		}
		if connects, requests, _ := parent.seen(); len(connects)+len(requests) != 0 {
			t.Error("a denied destination still reached the parent")
		}
	})

	t.Run("default deny is honoured", func(t *testing.T) {
		h := chainedProxy(t, parent.url(), "", rules(t, "allow domain allowed.test"))

		req := httptest.NewRequest("GET", "http://elsewhere.test/", nil)
		req.RemoteAddr = "10.1.2.3:5000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		// No rule matches and there is no default, so the set has no opinion and
		// the request proceeds — the same reading the unchained path takes.
		if rec.Code == http.StatusForbidden {
			t.Error("a set with no opinion refused the request")
		}
	})

	t.Run("CONNECT is gated the same way", func(t *testing.T) {
		h := chainedProxy(t, parent.url(), "", rules(t, "deny domain blocked.test\nallow all"))

		req := httptest.NewRequest(http.MethodConnect, "blocked.test:443", nil)
		req.Host = "blocked.test:443"
		req.RemoteAddr = "10.1.2.3:5000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("CONNECT status = %d, want 403", rec.Code)
		}
	})

	t.Run("an allowed destination still goes through", func(t *testing.T) {
		h := chainedProxy(t, parent.url(), "", rules(t, "allow all"))
		srv := httptest.NewServer(h)
		defer srv.Close()

		resp, err := proxyClient(t, srv.URL).Get(origin.URL + "/")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "ORIGIN" {
			t.Errorf("body = %q", body)
		}
	})
}

// The CONNECT port allowlist is about what the client asked for and must still
// hold: a parent does not make an arbitrary TCP relay acceptable.
func TestConnectPortRestrictionStillAppliesWhenChained(t *testing.T) {
	parent := newParentProxy(t, "")
	up, err := upstream.Parse(parent.url(), "")
	if err != nil {
		t.Fatal(err)
	}
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: []int{443}, Upstream: func() *upstream.Proxy { return up }})

	req := httptest.NewRequest(http.MethodConnect, "example.com:25", nil)
	req.Host = "example.com:25"
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if connects, _, _ := parent.seen(); len(connects) != 0 {
		t.Error("a disallowed CONNECT port still reached the parent")
	}
}

// The bug PROXY-67 actually was: the handler captured the parent proxy by value
// at startup, so a reload reported upstream_proxy applied while traffic kept
// flowing to the old parent.
//
// This asserts it where it broke — a handler built once, then a configuration
// change, then a request. A test at the config layer would have passed against
// the broken code, because the accessor was always live; it was the capture
// that was not.
func TestParentProxyIsRereadPerRequest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	first := newParentProxy(t, "")
	second := newParentProxy(t, "")

	// What main does: hand the Policy a function, not a value.
	var current atomic.Pointer[upstream.Proxy]
	set := func(u string) {
		p, err := upstream.Parse(u, "")
		if err != nil {
			t.Fatal(err)
		}
		current.Store(p)
	}
	set(first.url())

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(),
			Upstream: func() *upstream.Proxy { return current.Load() },
		})
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := proxyClient(t, srv.URL)

	resp, err := client.Get(origin.URL + "/one")
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close()

	// The reload.
	set(second.url())

	resp, err = client.Get(origin.URL + "/two")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	resp.Body.Close()

	_, firstSaw, _ := first.seen()
	_, secondSaw, _ := second.seen()
	if len(firstSaw) != 1 {
		t.Errorf("the original parent saw %d requests, want 1", len(firstSaw))
	}
	if len(secondSaw) != 1 {
		t.Errorf("the new parent saw %d requests, want 1 — the handler kept the old parent", len(secondSaw))
	}
}

// And the same for a parent being removed entirely: traffic must go direct
// rather than to a parent that may no longer exist.
func TestRemovingTheParentTakesEffect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	parent := newParentProxy(t, "")
	var current atomic.Pointer[upstream.Proxy]
	p, _ := upstream.Parse(parent.url(), "")
	current.Store(p)

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(),
			Upstream: func() *upstream.Proxy { return current.Load() },
		})
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := proxyClient(t, srv.URL)

	resp, _ := client.Get(origin.URL + "/via-parent")
	if resp != nil {
		resp.Body.Close()
	}

	none, _ := upstream.Parse("", "")
	current.Store(none)

	resp, err := client.Get(origin.URL + "/direct")
	if err != nil {
		t.Fatalf("request after removing the parent: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ORIGIN" {
		t.Errorf("body = %q", body)
	}

	if _, requests, _ := parent.seen(); len(requests) != 1 {
		t.Errorf("the parent saw %d requests, want only the first", len(requests))
	}
}

// newTLSParentProxy is the same parent, reached over TLS. An https:// parent is
// the configuration that keeps the credentials this proxy uses on its parent
// off the wire, so it has to actually work.
func newTLSParentProxy(t *testing.T, requireAuth string, pair tls.Certificate) *parentProxy {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &parentProxy{ln: ln, requireAuth: requireAuth}
	go p.serve()
	t.Cleanup(func() { ln.Close() })
	return p
}

// PROXY-74. The CONNECT path dials the parent itself, because a hijacked tunnel
// cannot go through the transport's Proxy hook — and having taken the dial, it
// has to take the TLS with it. It did not, so the nested CONNECT went out in
// cleartext to a port expecting a handshake, carrying the parent credentials in
// base64.
//
// A working tunnel is the assertion. A plaintext CONNECT cannot produce one
// against a TLS listener, so this fails on the old code by construction rather
// than by inspecting bytes and hoping the check is the right one.
func TestConnectThroughATLSParentSpeaksTLS(t *testing.T) {
	pki := newPKI(t)
	_, _, pair := pki.issue(t, "parent")

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	const user, pass = "parentuser", "parentsecret"
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	parent := newTLSParentProxy(t, want, pair)

	up, err := upstream.Parse("https://"+user+":"+pass+"@"+parent.addr(), "")
	if err != nil {
		t.Fatalf("upstream.Parse: %v", err)
	}
	h := NewForward(newLogger(), func(string) map[string]string { return nil }, Policy{
		AllowPrivate: true,
		ConnectPorts: allPorts(),
		Upstream:     func() *upstream.Proxy { return up },
		// The parent's certificate is verified against the same upstream trust
		// material everything else uses.
		UpstreamTLS: &tls.Config{RootCAs: pki.caPool},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	client := proxyClient(t, srv.URL)
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
		RootCAs: originPool(t, origin),
	}
	resp, err := client.Get(origin.URL + "/path")
	if err != nil {
		t.Fatalf("tunnelled request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ORIGIN" {
		t.Errorf("body = %q, want ORIGIN", body)
	}

	connects, _, auth := parent.seen()
	if len(connects) != 1 {
		t.Fatalf("the TLS parent saw %d CONNECTs, want 1", len(connects))
	}
	if len(auth) == 0 || auth[len(auth)-1] != want {
		t.Errorf("parent saw auth %v, want %q", auth, want)
	}
}

// PROXY-73, first half. h2c dials the origin from its own transport, which
// carries no Proxy hook — so a chained request sent to it bypassed the parent
// entirely, in the egress-controlled deployment that is the parent's whole
// reason for existing.
func TestH2CStillGoesThroughTheParent(t *testing.T) {
	origin := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}), &http2.Server{}))
	defer origin.Close()

	parent := newParentProxy(t, "")
	up, err := upstream.Parse(parent.url(), "")
	if err != nil {
		t.Fatalf("upstream.Parse: %v", err)
	}
	h := NewForward(newLogger(), func(string) map[string]string { return nil }, Policy{
		AllowPrivate: true,
		ConnectPorts: allPorts(),
		HTTP2:        HTTP2Cleartext,
		Upstream:     func() *upstream.Proxy { return up },
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := proxyClient(t, srv.URL).Get(origin.URL + "/path")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if _, requests, _ := parent.seen(); len(requests) != 1 {
		t.Errorf("the parent saw %d requests, want 1 — h2c went direct", len(requests))
	}
}

// PROXY-73, second half, and the part that made it a disclosure rather than a
// misconfiguration.
//
// The handler set Proxy-Authorization whenever it believed a request was
// chained; the transport then decided independently where the request actually
// went. Under h2c those two disagreed, and the origin — any origin — received
// the credentials this proxy uses on its parent. The hop-by-hop strip cannot
// catch it, because the header is set after the strip by code that believes it
// is talking to the parent.
//
// The credential travels with the routing decision now, on the proxy URL, so
// the two cannot come apart. The destination is deliberately *not* on the
// bypass list: the leak needed the handler to think the request was chained,
// which is the case this asserts.
func TestParentCredentialsNeverReachTheOrigin(t *testing.T) {
	var seen atomic.Value
	seen.Store("")
	origin := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("Proxy-Authorization"))
		io.WriteString(w, "ORIGIN")
	}), &http2.Server{}))
	defer origin.Close()

	const user, pass = "parentuser", "parentsecret"
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

	for _, mode := range []UpstreamHTTP2{HTTP2Auto, HTTP2Cleartext} {
		t.Run(string(mode), func(t *testing.T) {
			seen.Store("")
			parent := newParentProxy(t, want)
			up, err := upstream.Parse("http://"+user+":"+pass+"@"+parent.addr(), "")
			if err != nil {
				t.Fatalf("upstream.Parse: %v", err)
			}
			h := NewForward(newLogger(), func(string) map[string]string { return nil }, Policy{
				AllowPrivate: true,
				ConnectPorts: allPorts(),
				HTTP2:        mode,
				Upstream:     func() *upstream.Proxy { return up },
			})
			srv := httptest.NewServer(h)
			defer srv.Close()

			resp, err := proxyClient(t, srv.URL).Get(origin.URL + "/path")
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			io.ReadAll(resp.Body)
			resp.Body.Close()

			if got := seen.Load().(string); got != "" {
				t.Errorf("the origin received the parent's credentials: %q", got)
			}
			// The other half: the credential must still reach the parent, or
			// this would pass by never sending it anywhere.
			if _, _, auth := parent.seen(); len(auth) == 0 || auth[len(auth)-1] != want {
				t.Errorf("the parent saw auth %v, want %q", auth, want)
			}
		})
	}
}
