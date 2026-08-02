package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// heldListener accepts and keeps every connection, so nothing but the proxy
// decides when a tunnel ends. An earlier version of this test let the far side
// fall out of scope and be closed by the garbage collector, which quietly
// released two thirds of the tunnels and made the numbers meaningless.
type heldListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newHeldListener(t *testing.T) *heldListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &heldListener{Listener: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns = append(h.conns, c)
			h.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		h.mu.Lock()
		for _, c := range h.conns {
			c.Close()
		}
		h.mu.Unlock()
	})
	return h
}

func openTunnel(t *testing.T, proxyAddr, dest string) (net.Conn, int) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	io.WriteString(c, "CONNECT "+dest+" HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		c.Close()
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	return c, resp.StatusCode
}

// PROXY-87. A quota bounds the rate a client acquires tunnels. Nothing bounded
// how many it held, and a tunnel is acquired once and kept: 300 idle CONNECTs
// held 300 tunnels and 604 goroutines with nothing to reclaim them.
func TestTunnelCeilingIsEnforced(t *testing.T) {
	dest := newHeldListener(t)
	var refusals atomic.Int64
	var scopes []DeniedScope
	var mu sync.Mutex

	pol := Policy{
		AllowPrivate: true, ConnectPorts: allPorts(),
		Tunnels: &TunnelLimit{PerClient: 5, Global: 8},
	}
	h := NewForward(newLogger(), func(string) map[string]string { return nil }, pol,
		Observer{Denied: func(s DeniedScope) {
			refusals.Add(1)
			mu.Lock()
			scopes = append(scopes, s)
			mu.Unlock()
		}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()

	for i := 0; i < 5; i++ {
		c, code := openTunnel(t, addr, dest.Addr().String())
		open = append(open, c)
		if code != http.StatusOK {
			t.Fatalf("tunnel %d refused with %d, want 200", i+1, code)
		}
	}
	// The sixth from the same address is over the per-client ceiling.
	c, code := openTunnel(t, addr, dest.Addr().String())
	open = append(open, c)
	if code != http.StatusServiceUnavailable {
		t.Errorf("the sixth tunnel got %d, want 503", code)
	}
	if refusals.Load() != 1 {
		t.Errorf("refusals = %d, want 1 — a refusal must be counted like any other", refusals.Load())
	}
	mu.Lock()
	if len(scopes) != 1 || scopes[0] != ScopeTunnelClient {
		t.Errorf("refusal scope = %v, want %q", scopes, ScopeTunnelClient)
	}
	mu.Unlock()

	// Closing one gives the slot back, so the ceiling is a ceiling and not a
	// lifetime budget.
	held, _ := pol.Tunnels.Held()
	if held != 5 {
		t.Fatalf("held = %d, want 5", held)
	}
	open[0].Close()
	for i := 0; i < 100 && held != 4; i++ {
		time.Sleep(10 * time.Millisecond)
		held, _ = pol.Tunnels.Held()
	}
	if held != 4 {
		t.Errorf("after closing one, held = %d, want 4", held)
	}
	if _, code := openTunnel(t, addr, dest.Addr().String()); code != http.StatusOK {
		t.Errorf("a freed slot was not reusable: %d", code)
	}
}

// And without a limit the old behaviour is unchanged, so nobody's deployment
// acquires a ceiling by upgrading.
func TestNoTunnelLimitIsStillUnlimited(t *testing.T) {
	dest := newHeldListener(t)
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts()})
	srv := httptest.NewServer(h)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	for i := 0; i < 40; i++ {
		c, code := openTunnel(t, addr, dest.Addr().String())
		open = append(open, c)
		if code != http.StatusOK {
			t.Fatalf("tunnel %d refused with %d under no limit", i+1, code)
		}
	}
}

// The idle deadline, which is what reclaims a tunnel nobody is using. Off by
// default, because plenty of legitimate tunnels are quiet for long stretches.
func TestIdleTunnelsAreReclaimed(t *testing.T) {
	dest := newHeldListener(t)
	var closed atomic.Int64
	pol := Policy{
		AllowPrivate: true, ConnectPorts: allPorts(),
		Tunnels: &TunnelLimit{IdleTimeout: 150 * time.Millisecond},
	}
	h := NewForward(newLogger(), func(string) map[string]string { return nil }, pol,
		Observer{TunnelClosed: func() { closed.Add(1) }})
	srv := httptest.NewServer(h)
	defer srv.Close()

	before := runtime.NumGoroutine()
	c, code := openTunnel(t, strings.TrimPrefix(srv.URL, "http://"), dest.Addr().String())
	defer c.Close()
	if code != http.StatusOK {
		t.Fatalf("tunnel refused: %d", code)
	}

	deadline := time.Now().Add(5 * time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if closed.Load() == 0 {
		t.Fatalf("an idle tunnel survived its deadline; goroutines %d -> %d",
			before, runtime.NumGoroutine())
	}
	if held, _ := pol.Tunnels.Held(); held != 0 {
		t.Errorf("held = %d after the tunnel was reclaimed, want 0", held)
	}
}

// A slot must come back on every path that fails after taking one, or the
// ceiling leaks downward until it refuses everything.
func TestRefusedTunnelDoesNotLeakASlot(t *testing.T) {
	pol := Policy{
		AllowPrivate: true, ConnectPorts: allPorts(),
		Tunnels: &TunnelLimit{PerClient: 2},
	}
	h := NewForward(newLogger(), func(string) map[string]string { return nil }, pol)
	srv := httptest.NewServer(h)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	// Ten CONNECTs to a port nothing is listening on: each takes a slot, fails
	// to dial, and must give it back.
	for i := 0; i < 10; i++ {
		c, _ := openTunnel(t, addr, "127.0.0.1:1")
		c.Close()
	}
	if held, _ := pol.Tunnels.Held(); held != 0 {
		t.Errorf("held = %d after ten failed dials, want 0 — slots leaked", held)
	}
}
