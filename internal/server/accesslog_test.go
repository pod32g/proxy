package server

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pod32g/proxy/internal/config"
	log "github.com/pod32g/simple-logger"
)

// exchanges collects completion records from every goroutine that produces one.
type exchanges struct {
	mu   sync.Mutex
	list []Exchange
}

func (e *exchanges) add(x Exchange) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.list = append(e.list, x)
}

func (e *exchanges) all() []Exchange {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Exchange(nil), e.list...)
}

func TestParseAccessLogFormat(t *testing.T) {
	for _, in := range []string{"off", "structured", "combined", "  Combined ", "OFF"} {
		if _, err := ParseAccessLogFormat(in); err != nil {
			t.Errorf("ParseAccessLogFormat(%q): %v", in, err)
		}
	}
	// A typo must not quietly disable the access log.
	if _, err := ParseAccessLogFormat("json"); err == nil {
		t.Error("accepted an unknown access log format")
	}
}

func TestAccessLogOffProducesNoHook(t *testing.T) {
	logger, _ := config.NewLogger(io.Discard, log.INFO, "text")
	if NewAccessLog("off", logger, &bytes.Buffer{}) != nil {
		t.Error("off should produce a nil hook, so the record is never built")
	}
}

func TestExchangeRecordsStatusBytesAndDuration(t *testing.T) {
	var got exchanges
	body := strings.Repeat("x", 4096)
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, body)
	}), Accounting{Completed: got.add})

	req := httptest.NewRequest("POST", "http://example.com/a/b", strings.NewReader("hello"))
	req.RemoteAddr = "10.1.2.3:5000"
	h.ServeHTTP(httptest.NewRecorder(), req)

	all := got.all()
	if len(all) != 1 {
		t.Fatalf("got %d records, want 1", len(all))
	}
	e := all[0]
	if e.Client != "10.1.2.3" || e.Method != "POST" || e.Host != "example.com" || e.Path != "/a/b" {
		t.Errorf("got %+v", e)
	}
	if e.Status != http.StatusTeapot {
		t.Errorf("status = %d, want 418", e.Status)
	}
	if e.BytesIn != 5 {
		t.Errorf("bytes in = %d, want 5", e.BytesIn)
	}
	if e.BytesOut != int64(len(body)) {
		t.Errorf("bytes out = %d, want %d", e.BytesOut, len(body))
	}
	if e.Duration <= 0 {
		t.Error("duration was not recorded")
	}
	if e.Tunnel {
		t.Error("an ordinary request was recorded as a tunnel")
	}
}

// A handler that writes without calling WriteHeader has implicitly sent a 200,
// and a log that reported 0 there would be wrong on the most common path.
func TestExchangeDefaultsToTwoHundred(t *testing.T) {
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hi")
	}), Accounting{Completed: got.add})
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:1"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if s := got.all()[0].Status; s != http.StatusOK {
		t.Errorf("status = %d, want 200", s)
	}
}

// The acceptance criterion: a tunnel logged when it was established would
// report zero bytes and no duration. It has to be logged on close.
func TestTunnelIsLoggedOnCloseWithByteCounts(t *testing.T) {
	var got exchanges
	payload := strings.Repeat("z", 100<<10)

	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		// Nothing must be logged yet: the tunnel is open.
		if n := len(got.all()); n != 0 {
			t.Errorf("%d records logged at establishment, want 0", n)
		}
		conn.Write([]byte(payload))
		conn.Close()
	}), Accounting{Completed: got.add})

	srv := httptest.NewServer(h)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	io.WriteString(conn, req)
	io.Copy(io.Discard, conn)
	conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if all := got.all(); len(all) > 0 {
			e := all[0]
			if !e.Tunnel {
				t.Error("tunnel flag not set")
			}
			if e.Host != "example.com:443" {
				t.Errorf("host = %q, want the CONNECT target", e.Host)
			}
			if e.BytesOut < int64(len(payload)) {
				t.Errorf("bytes out = %d, want at least %d", e.BytesOut, len(payload))
			}
			if len(all) != 1 {
				t.Errorf("got %d records for one tunnel, want 1", len(all))
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("tunnel was never logged")
}

// Query strings can carry session tokens and API keys. A proxy cannot know
// which parameter is which, so the whole query is dropped rather than
// half-redacted.
func TestQueryStringIsNeverLogged(t *testing.T) {
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Accounting{Completed: got.add})

	req := httptest.NewRequest("GET", "http://example.com/search?token=s3cret&q=hi", nil)
	req.RemoteAddr = "10.1.2.3:1"
	h.ServeHTTP(httptest.NewRecorder(), req)

	e := got.all()[0]
	if strings.Contains(e.Path, "s3cret") || strings.Contains(e.Path, "?") {
		t.Errorf("path = %q, want the query dropped", e.Path)
	}
	if e.Path != "/search" {
		t.Errorf("path = %q, want %q", e.Path, "/search")
	}
}

func TestUserinfoIsStrippedFromTheHost(t *testing.T) {
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Accounting{Completed: got.add})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Host = "admin:hunter2@example.com"
	req.URL.Host = "admin:hunter2@example.com"
	req.RemoteAddr = "10.1.2.3:1"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if h := got.all()[0].Host; strings.Contains(h, "hunter2") {
		t.Errorf("host = %q, want the credential stripped", h)
	}
}

func TestStructuredAccessLogFields(t *testing.T) {
	var buf bytes.Buffer
	logger, err := config.NewLogger(&buf, log.INFO, "json")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	hook := NewAccessLog("structured", logger, nil)
	hook(Exchange{
		Client: "10.1.2.3", Method: "GET", Host: "example.com", Path: "/a",
		Status: 200, BytesIn: 12, BytesOut: 3400, Duration: 5 * time.Millisecond,
	})

	out := buf.String()
	for _, want := range []string{
		`"client":"10.1.2.3"`, `"method":"GET"`, `"host":"example.com"`,
		`"status":200`, `"bytes_in":12`, `"bytes_out":3400`, `"path":"/a"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	// INFO, not DEBUG: a level nobody runs in production is the same as no log.
	if !strings.Contains(out, `"level":"INFO"`) {
		t.Errorf("not logged at INFO: %s", out)
	}
}

func TestCombinedAccessLogFormat(t *testing.T) {
	var buf bytes.Buffer
	hook := NewAccessLog("combined", nil, &buf)
	hook(Exchange{
		Client: "10.1.2.3", Method: "GET", Host: "example.com", Path: "/a/b",
		Status: 404, BytesOut: 153,
	})

	line := buf.String()
	if !strings.HasPrefix(line, "10.1.2.3 - - [") {
		t.Errorf("bad prefix: %q", line)
	}
	if !strings.Contains(line, `"GET example.com/a/b HTTP/1.1" 404 153 "-" "-"`) {
		t.Errorf("bad request/status section: %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Error("line is not terminated")
	}
}

// A log format is a parser, and the request line is attacker-controlled input.
// A quote or a newline in the target must not be able to forge a record.
func TestCombinedAccessLogNeutralisesInjection(t *testing.T) {
	var buf bytes.Buffer
	hook := NewAccessLog("combined", nil, &buf)
	hook(Exchange{
		Client: "10.1.2.3", Method: "GET", Status: 200,
		Host: "evil.test", Path: "/a\" 200 0 \"-\" \"-\"\n10.9.9.9 - - [forged]",
	})

	out := buf.String()
	if strings.Count(out, "\n") != 1 {
		t.Errorf("injected newline produced %d lines: %q", strings.Count(out, "\n"), out)
	}
	if strings.Contains(out, `/a" 200`) {
		t.Errorf("injected quote was not escaped: %q", out)
	}
}
