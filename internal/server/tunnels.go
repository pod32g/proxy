package server

import (
	"context"
	"sync"
	"time"
)

// TunnelRegistry tracks hijacked connections so shutdown can close them.
//
// http.Server.Shutdown does not track a connection once it has been hijacked —
// reasonably, since it no longer speaks HTTP on it. But the access record for a
// tunnel is written by its Close, so nothing closing it meant nothing writing
// it: a tunnel open when the process exited produced no record at any point,
// not at establishment by design and not at close because close never came.
//
// Restarts are routine and this proxy has more reasons for them than most, so
// that was every long-lived session at every restart missing from the record —
// and a missing record looks exactly like an absence of traffic.
type TunnelRegistry struct {
	mu    sync.Mutex
	conns map[*accountedConn]struct{}
}

func NewTunnelRegistry() *TunnelRegistry {
	return &TunnelRegistry{conns: make(map[*accountedConn]struct{})}
}

func (r *TunnelRegistry) add(c *accountedConn) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.mu.Unlock()
}

func (r *TunnelRegistry) remove(c *accountedConn) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

// Len is how many tunnels are open.
func (r *TunnelRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

// CloseAll closes every open tunnel, marking each as ended by shutdown rather
// than by either peer, and returns how many it closed.
//
// Closing is what writes the record: accountedConn.Close calls finish, which
// flushes the pending byte charge and emits the exchange. So this is not a
// courtesy to the client — the process is going away regardless — it is the
// only way the tunnel appears in the log at all.
func (r *TunnelRegistry) CloseAll() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	open := make([]*accountedConn, 0, len(r.conns))
	for c := range r.conns {
		open = append(open, c)
	}
	r.mu.Unlock()

	for _, c := range open {
		c.w.shutdown.Store(true)
		c.Close()
	}
	return len(open)
}

// Wait blocks until every tunnel has finished reporting, or the context is
// done.
//
// Bounded by the caller's context, because a tunnel that will not close must
// not hold up a shutdown indefinitely — the records are worth waiting a moment
// for and not worth hanging on.
func (r *TunnelRegistry) Wait(ctx context.Context) {
	if r == nil {
		return
	}
	for r.Len() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}
