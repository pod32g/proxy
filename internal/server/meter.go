package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync/atomic"
)

// MeterMiddleware counts the bytes a client moves through the proxy and reports
// them once the exchange is over.
//
// This lives here rather than in the proxy handlers because the traffic worth
// counting is exactly the traffic a handler cannot see. A CONNECT tunnel and a
// WebSocket upgrade are both served by hijacking the connection and splicing
// two sockets together; nothing after that point passes through ResponseWriter.
// Wrapping the hijacked connection as well as the writer catches tunnels,
// upgrades and ordinary responses with one piece of code, and leaves the proxy
// package unaware that metering exists at all.
//
// Both directions are counted. On an egress proxy the bytes a client uploads
// cost the operator the same as the bytes it downloads, and a quota that
// counted only responses would be trivially avoided by a large POST.
func MeterMiddleware(next http.Handler, meter func(client string, n int64)) http.Handler {
	if next == nil || meter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := hostOnly(r.RemoteAddr)
		m := &meteredWriter{ResponseWriter: w}
		if r.Body != nil {
			r.Body = &meteredBody{ReadCloser: r.Body, n: &m.n}
		}

		// A hijacked connection outlives the handler, so its bytes are reported
		// as they are counted rather than at the end. Everything else is
		// reported once, when the handler returns.
		m.report = func(n int64) { meter(client, n) }
		next.ServeHTTP(m, r)
		if !m.hijacked.Load() {
			if n := m.n.Swap(0); n > 0 {
				meter(client, n)
			}
		}
	})
}

type meteredWriter struct {
	http.ResponseWriter
	n        atomic.Int64
	hijacked atomic.Bool
	report   func(int64)
}

func (m *meteredWriter) Write(b []byte) (int, error) {
	n, err := m.ResponseWriter.Write(b)
	m.n.Add(int64(n))
	return n, err
}

func (m *meteredWriter) WriteHeader(code int) { m.ResponseWriter.WriteHeader(code) }

// SetStatus forwards to the metrics recorder underneath, which is what actually
// records a hijacked protocol switch.
func (m *meteredWriter) SetStatus(code int) {
	if s, ok := m.ResponseWriter.(interface{ SetStatus(int) }); ok {
		s.SetStatus(code)
	}
}

func (m *meteredWriter) Flush() {
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (m *meteredWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := m.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Hijack hands back a connection that keeps counting. The tunnel it becomes may
// run for hours, so it reports in chunks as traffic flows instead of waiting for
// a close that might never come while the quota it feeds sits idle.
func (m *meteredWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := m.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, buf, err
	}
	m.hijacked.Store(true)
	// Flush what the exchange cost before the switch — the request headers and
	// any body already read.
	if n := m.n.Swap(0); n > 0 {
		m.report(n)
	}
	return &meteredConn{Conn: conn, report: m.report}, buf, nil
}

// meterChunk is how much a tunnel accumulates before reporting. Reporting every
// read would put a mutex acquisition on every packet; waiting for the tunnel to
// close would let a long-running transfer escape its quota entirely.
const meterChunk = 64 << 10

type meteredConn struct {
	net.Conn
	report  func(int64)
	pending atomic.Int64
}

func (c *meteredConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.add(int64(n))
	return n, err
}

func (c *meteredConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.add(int64(n))
	return n, err
}

func (c *meteredConn) add(n int64) {
	if n <= 0 {
		return
	}
	if total := c.pending.Add(n); total >= meterChunk {
		if c.pending.CompareAndSwap(total, 0) {
			c.report(total)
		}
	}
}

func (c *meteredConn) Close() error {
	if n := c.pending.Swap(0); n > 0 {
		c.report(n)
	}
	return c.Conn.Close()
}

type meteredBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b *meteredBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}
