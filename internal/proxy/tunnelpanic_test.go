package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pod32g/proxy/internal/server"
	log "github.com/pod32g/simple-logger"
)

// lockedBuffer lets the test read what a guarded goroutine is writing.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// PROXY-95, through the real stack. Accounting.Completed runs in the handler
// goroutine for an ordinary request and on the tunnel-close goroutine for a
// hijacked one. net/http recovers the first; nothing recovered the second, so
// a panicking access-log sink took the whole process down.
//
// This test completing at all is the assertion — an unguarded panic on that
// goroutine aborts the test binary rather than failing a case.
func TestAPanickingSinkDoesNotKillTheProcess(t *testing.T) {
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
			go func(c net.Conn) { io.Copy(io.Discard, c) }(c)
		}
	}()

	diag := &lockedBuffer{}
	lg, _ := log.New(log.WithOutput(diag), log.WithLevel(log.DEBUG))
	h := server.AccountingMiddleware(
		NewForward(lg, func(string) map[string]string { return nil },
			Policy{AllowPrivate: true, ConnectPorts: allPorts()}),
		server.Accounting{Completed: func(server.Exchange) { panic("a sink that panics") }})
	srv := httptest.NewServer(h)
	defer srv.Close()

	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "CONNECT "+dest.Addr().String()+" HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	resp.Body.Close()
	c.Close() // end the tunnel, which runs the sink on the splice goroutine

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(diag.String(), "Recovered from a panic") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(diag.String(), "Recovered from a panic") {
		t.Fatalf("the panic was not recovered and reported:\n%s", diag.String())
	}
	if !strings.Contains(diag.String(), "tunnel") {
		t.Errorf("the report does not name the goroutine:\n%s", diag.String())
	}
}
