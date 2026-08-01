package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pod32g/proxy/internal/reqid"
)

// Exchange is the record of one completed request, as the access log wants it.
type Exchange struct {
	Client   string
	Method   string
	Host     string
	Path     string
	Status   int
	BytesIn  int64
	BytesOut int64
	Duration time.Duration
	// RequestID identifies this exchange across the hop.
	RequestID string
	// Tunnel marks an exchange that was hijacked — a CONNECT tunnel or a
	// protocol upgrade. Its record arrives when the connection closes, not when
	// it was established, so the byte counts mean something.
	Tunnel bool
}

// Accounting is what the middleware does with what it observes.
type Accounting struct {
	// Charge is called as bytes move, possibly many times per exchange, with
	// the bytes read from and written to the client since the last call. Quotas
	// need the incremental form: a tunnel that runs for an hour must not escape
	// its allowance until it closes. Metrics want the direction split, and
	// reporting once for both keeps a single pass over the connection.
	Charge func(client string, in, out int64)
	// Completed is called once, when the exchange is over. For a hijacked
	// connection that is on close.
	Completed func(Exchange)
}

func (a Accounting) empty() bool { return a.Charge == nil && a.Completed == nil }

// AccountingMiddleware counts what a client moves through the proxy, in both
// directions, and reports it.
//
// This lives here rather than in the proxy handlers because the traffic worth
// counting is exactly the traffic a handler cannot see. A CONNECT tunnel and a
// WebSocket upgrade are both served by hijacking the connection and splicing
// two sockets together; nothing after that point passes through ResponseWriter.
// Wrapping the hijacked connection as well as the writer catches tunnels,
// upgrades and ordinary responses with one piece of code, and leaves the proxy
// package unaware that any of this exists.
//
// Both directions are counted. On an egress proxy the bytes a client uploads
// cost the operator the same as the bytes it downloads, and an accounting that
// looked only at responses would be sidestepped by a large POST.
func AccountingMiddleware(next http.Handler, acct Accounting) http.Handler {
	if next == nil || acct.empty() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := hostOnly(r.RemoteAddr)
		start := time.Now()

		// Assigned here, at the outermost layer, so that everything downstream —
		// the access log, the proxy handler's own warnings, the header sent
		// upstream — refers to the same exchange by the same name.
		id := reqid.FromRequestOrNew(r.Header.Get(reqid.Header))
		if id != "" {
			r = r.WithContext(reqid.WithID(r.Context(), id))
			// Echoed to the caller so they can correlate without reading our
			// logs, and set before the handler runs because a hijacked
			// connection never writes headers at all.
			w.Header().Set(reqid.Header, id)
		}

		m := &accountedWriter{
			ResponseWriter: w,
			client:         client,
			charge:         acct.Charge,
		}
		if r.Body != nil {
			r.Body = &accountedBody{ReadCloser: r.Body, w: m}
		}

		host, path := destination(r)
		m.exchange = Exchange{Client: client, Method: r.Method, Host: host, Path: path, RequestID: id}
		m.completed = acct.Completed
		m.start = start

		next.ServeHTTP(m, r)

		// A hijacked connection outlives the handler; its own Close reports it.
		if !m.hijacked.Load() {
			m.finish()
		}
	})
}

// destination reports where a request was headed, with anything credential-ish
// removed.
//
// The query string is dropped rather than redacted. A proxy cannot know which
// parameter carries the session token — plenty of APIs put one there — and a
// partial redaction that looks thorough is worse than an honest omission.
// Userinfo goes for the same reason: "http://user:pass@host/" is a credential
// sitting in the request line.
func destination(r *http.Request) (host, path string) {
	if r.Method == http.MethodConnect {
		// CONNECT carries its target in the request line, not the URL.
		return sanitizeHost(r.Host), ""
	}
	u := r.URL
	if u == nil {
		return sanitizeHost(r.Host), ""
	}
	host = u.Host
	if host == "" {
		host = r.Host
	}
	return sanitizeHost(host), redactPath(u)
}

func redactPath(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	// EscapedPath rather than Path so a control character in the request cannot
	// forge a line break in a text-format log.
	return u.EscapedPath()
}

// sanitizeHost strips userinfo that a client put in the authority.
func sanitizeHost(host string) string {
	if at := strings.LastIndex(host, "@"); at >= 0 {
		return host[at+1:]
	}
	return host
}

type accountedWriter struct {
	http.ResponseWriter
	client string
	charge func(client string, in, out int64)

	in  atomic.Int64
	out atomic.Int64
	// pending* are the bytes counted but not yet reported through Charge.
	pendingIn  atomic.Int64
	pendingOut atomic.Int64
	status     atomic.Int32
	hijacked   atomic.Bool

	start     time.Time
	exchange  Exchange
	completed func(Exchange)
	done      atomic.Bool
}

func (m *accountedWriter) Write(b []byte) (int, error) {
	if m.status.Load() == 0 {
		m.status.Store(http.StatusOK) // implicit 200, as net/http does
	}
	n, err := m.ResponseWriter.Write(b)
	m.out.Add(int64(n))
	m.chargedOut(int64(n))
	return n, err
}

func (m *accountedWriter) WriteHeader(code int) {
	m.status.Store(int32(code))
	m.ResponseWriter.WriteHeader(code)
}

// SetStatus records a status the handler could not write through WriteHeader,
// and forwards it to the metrics recorder underneath.
func (m *accountedWriter) SetStatus(code int) {
	m.status.Store(int32(code))
	if s, ok := m.ResponseWriter.(interface{ SetStatus(int) }); ok {
		s.SetStatus(code)
	}
}

func (m *accountedWriter) Flush() {
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (m *accountedWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := m.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// chargedIn and chargedOut batch the report. Reporting every write would put a
// mutex acquisition on every packet; waiting for the exchange to end would let a
// long-running transfer escape the quota it feeds.
func (m *accountedWriter) chargedIn(n int64) {
	if n <= 0 || m.charge == nil {
		return
	}
	if total := m.pendingIn.Add(n); total >= chargeChunk {
		m.flushCharge()
	}
}

func (m *accountedWriter) chargedOut(n int64) {
	if n <= 0 || m.charge == nil {
		return
	}
	if total := m.pendingOut.Add(n); total >= chargeChunk {
		m.flushCharge()
	}
}

// flushCharge reports and clears both directions together, so a tunnel that is
// busy in one direction still settles the other.
func (m *accountedWriter) flushCharge() {
	if m.charge == nil {
		return
	}
	in := m.pendingIn.Swap(0)
	out := m.pendingOut.Swap(0)
	if in > 0 || out > 0 {
		m.charge(m.client, in, out)
	}
}

// finish reports the exchange exactly once.
func (m *accountedWriter) finish() {
	if !m.done.CompareAndSwap(false, true) {
		return
	}
	m.flushCharge()
	if m.completed == nil {
		return
	}
	e := m.exchange
	e.Status = int(m.status.Load())
	if e.Status == 0 {
		// The handler neither wrote nor set a code. As far as the client is
		// concerned that is a 200.
		e.Status = http.StatusOK
	}
	e.BytesIn = m.in.Load()
	e.BytesOut = m.out.Load()
	e.Duration = time.Since(m.start)
	e.Tunnel = m.hijacked.Load()
	m.completed(e)
}

// chargeChunk is how much a transfer accumulates before the quota is charged.
const chargeChunk = 64 << 10

// Hijack hands back a connection that keeps counting, and defers the completion
// record to that connection's Close. A tunnel logged at establishment would
// report zero bytes and no duration, which is the number nobody wants.
func (m *accountedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := m.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, buf, err
	}
	m.hijacked.Store(true)
	// Flush what the exchange cost before the switch: the request headers and
	// any body already read.
	m.flushCharge()
	return &accountedConn{Conn: conn, w: m}, buf, nil
}

// accountedConn is the client side of a hijacked exchange. Read is traffic from
// the client, Write is traffic to it.
type accountedConn struct {
	net.Conn
	w      *accountedWriter
	closed atomic.Bool
}

func (c *accountedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.w.in.Add(int64(n))
		c.w.chargedIn(int64(n))
	}
	return n, err
}

func (c *accountedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.w.out.Add(int64(n))
		c.w.chargedOut(int64(n))
	}
	return n, err
}

// Close reports the tunnel. Both pump goroutines close their end, so this
// guards against reporting the same exchange twice.
func (c *accountedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.w.finish()
	}
	return c.Conn.Close()
}

type accountedBody struct {
	io.ReadCloser
	w *accountedWriter
}

func (b *accountedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.w.in.Add(int64(n))
		b.w.chargedIn(int64(n))
	}
	return n, err
}
