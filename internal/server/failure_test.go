package server

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	log "github.com/pod32g/simple-logger"
)

// PROXY-96. finish() ran after ServeHTTP and not in a defer, so a panic
// unwound straight past it: net/http recovered, the client got a dropped
// connection, and the exchange left no access record and no charge against the
// byte quota. The requests that panic are exactly the ones worth a record of.
func TestAPanickingHandlerIsStillRecorded(t *testing.T) {
	var diag bytes.Buffer
	lg, err := log.New(log.WithOutput(&diag), log.WithLevel(log.DEBUG))
	if err != nil {
		t.Fatal(err)
	}
	var got Exchange
	var records int
	var charged int64
	h := AccountingMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("boom")
		}),
		Accounting{
			Logger:    lg,
			Completed: func(e Exchange) { got, records = e, records+1 },
			Charge:    func(_ string, in, out int64) { charged += in + out },
		})

	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	// No recover here: the middleware has to survive it on its own, so that a
	// panic is a 500 with a stack rather than a dropped connection.
	h.ServeHTTP(rec, req)

	if records != 1 {
		t.Fatalf("access records = %d, want 1", records)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("client got %d, want 500", rec.Code)
	}
	if got.Status != http.StatusInternalServerError {
		t.Errorf("recorded status = %d, want 500", got.Status)
	}
	if !got.Incomplete {
		t.Error("the record does not mark the exchange as unfinished")
	}
	if !strings.Contains(diag.String(), "Handler panicked") {
		t.Errorf("the panic was not logged:\n%s", diag.String())
	}
	if !strings.Contains(diag.String(), "stack") {
		t.Error("the panic was logged without a stack")
	}
	_ = charged
}

// A handler that panics after writing keeps the status it already sent — that
// is on the wire and cannot be corrected — but is still recorded and still
// charged for what it moved.
func TestAPanicAfterWritingStillChargesAndRecords(t *testing.T) {
	var got Exchange
	var charged int64
	h := AccountingMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(bytes.Repeat([]byte("x"), 100))
			panic("boom")
		}),
		Accounting{
			Completed: func(e Exchange) { got = e },
			Charge:    func(_ string, in, out int64) { charged += in + out },
		})
	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.Status != http.StatusOK {
		t.Errorf("recorded status = %d, want the 200 already sent", got.Status)
	}
	if got.BytesOut != 100 {
		t.Errorf("recorded bytes_out = %d, want 100", got.BytesOut)
	}
	if charged != 100 {
		t.Errorf("charged %d bytes to the quota, want 100", charged)
	}
	if !got.Incomplete {
		t.Error("the record does not mark the exchange as unfinished")
	}
}

// PROXY-97. The access record for a tunnel is written by its Close, and
// Shutdown does not know hijacked connections exist — so a tunnel open at exit
// produced no record at any point.
func TestATunnelOpenAtShutdownIsRecorded(t *testing.T) {
	dest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	go func() {
		for {
			c, err := dest.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	var records []Exchange
	registry := NewTunnelRegistry()
	handler := AccountingMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			// Held open, like a real tunnel with nothing to say.
		}),
		Accounting{
			Tunnels:   registry,
			Completed: func(e Exchange) { records = append(records, e) },
		})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "CONNECT "+dest.Addr().String()+" HTTP/1.1\r\nHost: x\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	if registry.Len() != 1 {
		t.Fatalf("registry holds %d tunnels, want 1", registry.Len())
	}
	if len(records) != 0 {
		t.Fatalf("a live tunnel was recorded early: %+v", records)
	}

	// What Server.Start does at shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	if n := registry.CloseAll(); n != 1 {
		t.Fatalf("CloseAll closed %d, want 1", n)
	}
	registry.Wait(ctx)

	if len(records) != 1 {
		t.Fatalf("a tunnel open at shutdown left %d records, want 1", len(records))
	}
	if !records[0].Tunnel {
		t.Error("the record is not marked as a tunnel")
	}
	if !records[0].ShutdownClosed {
		t.Error("the record does not say it was ended by shutdown rather than by a peer")
	}
	if registry.Len() != 0 {
		t.Errorf("registry still holds %d tunnels after they reported", registry.Len())
	}
}

// Shutdown must not hang on a tunnel that will not report.
func TestShutdownWaitIsBounded(t *testing.T) {
	r := NewTunnelRegistry()
	r.conns[&accountedConn{}] = struct{}{} // never removed
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	r.Wait(ctx)
	if d := time.Since(start); d > time.Second {
		t.Errorf("Wait took %v; it must be bounded by the context", d)
	}
}
