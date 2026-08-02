package proxy

import (
	"io"
	"net"
	"sync"
	"time"
)

// TunnelLimit bounds how many hijacked connections may be held at once.
//
// The quota package bounds two things and says so: requests per second, and
// bytes. Neither bounds what a client *holds*. A CONNECT tunnel is one request
// against the rate limit and then lives as long as the client wants it to, so
// a request quota governs the rate of acquisition and says nothing about the
// stock — which for something long-lived is the only figure that matters. At
// `client requests 50/s`, a deliberately tight setting, a client opens fifty
// tunnels a second forever and reaches a 1024-descriptor limit in ten seconds.
//
// Observer.TunnelOpened's comment already noted that "tunnels are long-lived
// and a request counter sees each one exactly once", which is exactly why the
// request counter cannot bound them. This is the conclusion that observation
// implies.
//
// The zero value is unlimited, which is what the proxy did before and what it
// still does unless an operator chooses otherwise. No default was invented:
// a browser holds a handful of tunnels and a NAT gateway serving a thousand
// users holds thousands, and a number that fits one breaks the other. What has
// changed is that the limit exists, is reported at startup, and is enforced
// when set.
type TunnelLimit struct {
	// PerClient caps tunnels held by one source address. Zero is unlimited.
	PerClient int
	// Global caps tunnels across every client at once. Zero is unlimited.
	Global int

	// IdleTimeout closes a tunnel neither side has moved bytes on for this
	// long. Zero disables it, which is the default: a hijacked connection is
	// out of net/http's hands, so nothing else reclaims one — but plenty of
	// legitimate tunnels are idle for long stretches (SSH over CONNECT, a
	// long-poll, an open WebSocket), and a proxy that severs them is worse than
	// one that holds them. An operator who knows their traffic can say.
	IdleTimeout time.Duration

	mu      sync.Mutex
	total   int
	perAddr map[string]int
}

// Unlimited reports whether the limit constrains anything.
func (l *TunnelLimit) Unlimited() bool {
	return l == nil || (l.PerClient <= 0 && l.Global <= 0)
}

// Acquire takes a slot for a client, reporting whether one was available and
// which ceiling refused it.
func (l *TunnelLimit) Acquire(client string) (bool, DeniedScope) {
	if l == nil {
		return true, ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Global > 0 && l.total >= l.Global {
		return false, ScopeTunnelGlobal
	}
	if l.PerClient > 0 && l.perAddr[client] >= l.PerClient {
		return false, ScopeTunnelClient
	}
	if l.perAddr == nil {
		l.perAddr = make(map[string]int)
	}
	l.total++
	l.perAddr[client]++
	return true, ""
}

// Release returns a slot. The per-client entry is deleted at zero rather than
// left at zero, so the table is bounded by concurrent clients rather than by
// every client ever seen — the same rule the quota and auth-failure tables
// follow.
func (l *TunnelLimit) Release(client string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total > 0 {
		l.total--
	}
	if n, ok := l.perAddr[client]; ok {
		if n <= 1 {
			delete(l.perAddr, client)
		} else {
			l.perAddr[client] = n - 1
		}
	}
}

// Held reports the current totals, for tests and for reporting.
func (l *TunnelLimit) Held() (total, clients int) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, len(l.perAddr)
}

// idleConn closes a connection that has gone quiet.
//
// Deadlines rather than a timer: a deadline is what the socket already
// understands, and refreshing it on progress means an active tunnel never
// notices while an abandoned one fails its next read and unwinds through the
// existing close path.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) touch() {
	_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
}

func (c *idleConn) Read(b []byte) (int, error) {
	c.touch()
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	c.touch()
	return c.Conn.Write(b)
}

// idle wraps a spliced connection when an idle timeout is configured and the
// connection can carry a deadline.
//
// An upgraded connection's upstream side is the transport's ReadWriteCloser
// rather than a net.Conn, so it is returned unchanged rather than refused — the
// client side still carries the deadline, and either end closing tears down
// both, which is enough to reclaim the pair.
func (p Policy) idle(c io.ReadWriteCloser) io.ReadWriteCloser {
	if p.Tunnels == nil || p.Tunnels.IdleTimeout <= 0 {
		return c
	}
	conn, ok := c.(net.Conn)
	if !ok {
		return c
	}
	return &idleConn{Conn: conn, idle: p.Tunnels.IdleTimeout}
}
