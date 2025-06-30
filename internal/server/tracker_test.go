package server

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type stubAddr struct{ addr string }

func (s stubAddr) Network() string { return "tcp" }
func (s stubAddr) String() string  { return s.addr }

type stubConn struct {
	net.Conn
	raddr net.Addr
}

func (s stubConn) RemoteAddr() net.Addr { return s.raddr }

func TestClientTracker(t *testing.T) {
	ct := NewClientTracker()
	g := prometheus.NewGauge(prometheus.GaugeOpts{})
	ct.SetGauge(g)
	ch := ct.Subscribe()
	if <-ch != 0 {
		t.Fatalf("initial count")
	}

	c := stubConn{raddr: stubAddr{addr: "1.2.3.4:5"}}
	ct.ConnState(c, http.StateNew)
	if ct.Count() != 1 {
		t.Fatalf("count=1 expected")
	}
	if testutil.ToFloat64(g) != 1 {
		t.Fatalf("gauge not updated")
	}
	addrs := ct.Addrs()
	if len(addrs) != 1 || addrs[0] != "1.2.3.4" {
		t.Fatalf("addrs wrong: %v", addrs)
	}

	ct.ConnState(c, http.StateClosed)
	if ct.Count() != 0 {
		t.Fatalf("count=0 expected")
	}
	ct.Unsubscribe(ch)
	time.Sleep(10 * time.Millisecond) // allow async update
}
