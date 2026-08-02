package server

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/reqid"
	log "github.com/pod32g/simple-logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

// A caller that supplies its own identifier gets it back, propagates it, and
// sees it in the record. Replacing it would break correlation with whatever
// system upstream of us assigned it.
func TestInboundRequestIDIsHonouredEndToEnd(t *testing.T) {
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Accounting{Completed: got.add})

	const supplied = "0af7651916cd43dd8448eb211c80319c"
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:1"
	req.Header.Set(reqid.Header, supplied)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if id := got.all()[0].RequestID; id != supplied {
		t.Errorf("record id = %q, want the caller's %q", id, supplied)
	}
	// Echoed back so the caller can correlate without reading our logs.
	if v := rec.Header().Get(reqid.Header); v != supplied {
		t.Errorf("response header = %q, want %q", v, supplied)
	}
}

func TestRequestIDIsGeneratedWhenAbsent(t *testing.T) {
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Accounting{Completed: got.add})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	id := got.all()[0].RequestID
	if len(id) != 32 {
		t.Fatalf("id = %q, want a generated one", id)
	}
	if v := rec.Header().Get(reqid.Header); v != id {
		t.Errorf("response header = %q, want the same id %q", v, id)
	}
}

// A log line is a parser's input, and the id comes off a header. An id that
// could forge a record must never reach the log.
func TestUnusableRequestIDNeverReachesTheLog(t *testing.T) {
	var buf bytes.Buffer
	logger, err := config.NewLogger(&buf, log.INFO, "text")
	if err != nil {
		t.Fatal(err)
	}
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Accounting{Completed: func(e Exchange) {
			got.add(e)
			NewAccessLog("structured", logger, nil)(e)
		}})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:1"
	// net/http will not let a forged header through Set, so plant it directly.
	req.Header[reqid.Header] = []string{"abc\nlevel=INFO message=forged"}
	h.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(buf.String(), "forged") {
		t.Errorf("a forged id reached the log: %q", buf.String())
	}
	if id := got.all()[0].RequestID; len(id) != 32 {
		t.Errorf("id = %q, want it replaced with a generated one", id)
	}
}

// The tunnel record arrives from the close path, long after the handler
// returned, so the id has to survive that far.
func TestTunnelRecordCarriesTheRequestID(t *testing.T) {
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		conn.Write([]byte("x"))
		conn.Close()
	}), Accounting{Completed: got.add})

	srv := httptest.NewServer(h)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"+
		reqid.Header+": my-tunnel-id\r\n\r\n")
	io.Copy(io.Discard, conn)
	conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if all := got.all(); len(all) > 0 {
			if all[0].RequestID != "my-tunnel-id" {
				t.Errorf("tunnel record id = %q, want the caller's", all[0].RequestID)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("tunnel was never recorded")
}

// The accounting layer carries the served flag through to the completion
// record, including for tunnels, whose record is produced from the close path.
func TestExchangeCarriesServed(t *testing.T) {
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(interface{ SetServed() }).SetServed()
	}), Accounting{Completed: got.add})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:1"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !got.all()[0].Served {
		t.Error("Served was not carried into the record")
	}
}

func TestExchangeDefaultsToNotServed(t *testing.T) {
	var got exchanges
	h := AccountingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A handler that refuses writes a status and never forwards.
		w.WriteHeader(http.StatusForbidden)
	}), Accounting{Completed: got.add})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:1"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.all()[0].Served {
		t.Error("a refusal was recorded as served; the default must be false")
	}
}

// The signal has to survive the whole assembled stack, not just the accounting
// wrapper. The first version of this feature passed its unit tests against a
// bare writer while the real chain — accounting outside, metrics recorder in
// between — silently swallowed it, because the recorder did not forward the
// call. Every wrapper between the handler and the layer that cares has to.
func TestServedSurvivesTheAssembledMiddlewareStack(t *testing.T) {
	var got exchanges

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := w.(interface{ SetServed() })
		if !ok {
			t.Fatal("the handler cannot signal Served through this stack")
		}
		s.SetServed()
		w.Write([]byte("ok"))
	})

	metrics, err := NewMetrics(prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	// Exactly the order main assembles: accounting outermost, metrics inside.
	h := AccountingMiddleware(MetricsMiddleware(inner, metrics),
		Accounting{Completed: got.add})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:1"
	h.ServeHTTP(httptest.NewRecorder(), req)

	all := got.all()
	if len(all) != 1 {
		t.Fatalf("got %d records", len(all))
	}
	if !all[0].Served {
		t.Error("Served was swallowed between the handler and the accounting layer")
	}
}

// instrumented assembles the stack in the same order main does: accounting
// outermost, then metrics, then the Router. The order is the point of PROXY-63
// — with the Router outside, everything it refused produced no record at all.
func instrumented(t *testing.T, r *Router, got *exchanges) (http.Handler, *Metrics) {
	t.Helper()
	m, err := NewMetrics(prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	return AccountingMiddleware(MetricsMiddleware(r, m), Accounting{Completed: got.add}), m
}

// The bug: a request the Router refuses is proxy traffic and has to appear in
// both surfaces. Previously it appeared in neither, so the access log silently
// omitted exactly the requests an operator goes looking for.
func TestRouterRefusalsAreRecorded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		router func() *Router
		status int
	}{
		{
			name: "client table",
			router: func() *Router {
				return &Router{
					Proxy:         okHandler("PROXIED"),
					ClientAllowed: func(string) (bool, string) { return false, "default deny" },
				}
			},
			status: http.StatusForbidden,
		},
		{
			name: "quota",
			router: func() *Router {
				return &Router{
					Proxy: okHandler("PROXIED"),
					Quota: func(string) (bool, time.Duration, string) {
						return false, time.Second, "client-requests"
					},
				}
			},
			status: http.StatusTooManyRequests,
		},
		{
			name: "authentication",
			router: func() *Router {
				return &Router{
					Proxy: okHandler("PROXIED"),
					Auth:  func() (bool, string, string) { return true, "u", "p" },
				}
			},
			status: http.StatusProxyAuthRequired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got exchanges
			h, m := instrumented(t, tc.router(), &got)

			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = "10.1.2.3:5000"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			all := got.all()
			if len(all) != 1 {
				t.Fatalf("got %d access records, want exactly 1", len(all))
			}
			if all[0].Status != tc.status {
				t.Errorf("record status = %d, want %d", all[0].Status, tc.status)
			}
			// A refusal never reached a destination, so it must not be counted
			// as traffic to the host it was refused from.
			if all[0].Served {
				t.Error("a refused request was recorded as served")
			}
			if v := testutil.ToFloat64(
				m.Requests.WithLabelValues("GET", strconv.Itoa(tc.status), "")); v != 1 {
				t.Errorf("request counter = %v, want 1", v)
			}
		})
	}
}

// A refusal has to be attributable to the listener that refused it, or a
// multi-listener deployment cannot tell which policy did the refusing.
func TestRefusalsCarryTheListenerName(t *testing.T) {
	var got exchanges
	r := &Router{
		Proxy:         okHandler("PROXIED"),
		ClientAllowed: func(string) (bool, string) { return false, "deny" },
	}
	h, _ := instrumented(t, r, &got)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	WithListener(h, "external").ServeHTTP(httptest.NewRecorder(), req)

	all := got.all()
	if len(all) != 1 {
		t.Fatalf("got %d records", len(all))
	}
	if all[0].Listener != "external" {
		t.Errorf("listener = %q, want the refusing listener", all[0].Listener)
	}
}

// Health probes arrive every few seconds forever. Logging them would swamp the
// access log and counting them would put a constant floor under every
// request-rate graph.
func TestHealthProbesAreNotRecorded(t *testing.T) {
	var got exchanges
	r := &Router{Proxy: okHandler("PROXIED"), HealthPath: DefaultHealthPath}
	h, m := instrumented(t, r, &got)

	req := httptest.NewRequest("GET", DefaultHealthPath, nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("health probe got %d", rec.Code)
	}
	if n := len(got.all()); n != 0 {
		t.Errorf("%d access records for a health probe, want 0", n)
	}
	if v := testutil.CollectAndCount(m.Requests); v != 0 {
		t.Errorf("%d request series for a health probe, want 0", v)
	}
}

// An operator with a browser open is not proxy traffic. Counting the admin
// surface would make "requests to the proxy" mean two different things.
func TestAdminSurfaceIsNotRecordedAsProxyTraffic(t *testing.T) {
	for _, path := range []string{"/ui/general", "/api/policy", "/metrics"} {
		t.Run(path, func(t *testing.T) {
			var got exchanges
			r := &Router{
				Proxy: okHandler("PROXIED"), UI: okHandler("UI"),
				API: okHandler("API"), Metrics: okHandler("METRICS"),
			}
			h, m := instrumented(t, r, &got)

			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "10.1.2.3:5000"
			h.ServeHTTP(httptest.NewRecorder(), req)

			if n := len(got.all()); n != 0 {
				t.Errorf("%d access records for %s, want 0", n, path)
			}
			if v := testutil.CollectAndCount(m.Requests); v != 0 {
				t.Errorf("%d request series for %s, want 0", v, path)
			}
		})
	}
}

// A duplicated record would be worse than the missing one: it would silently
// double every rate computed from the log.
func TestProxiedRequestProducesExactlyOneRecord(t *testing.T) {
	var got exchanges
	r := &Router{Proxy: okHandler("PROXIED")}
	h, m := instrumented(t, r, &got)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if n := len(got.all()); n != 1 {
		t.Errorf("got %d access records, want exactly 1", n)
	}
	if v := testutil.ToFloat64(m.Requests.WithLabelValues("GET", "200", "")); v != 1 {
		t.Errorf("request counter = %v, want exactly 1", v)
	}
}

// PROXY-92. The write error was discarded, so a full disk or a rotation script
// that removed the file stopped the record silently — and an absence of entries
// reads as an absence of traffic to whoever is reconstructing an incident.
type flakyWriter struct {
	mu   sync.Mutex
	fail bool
	ok   int
}

func (f *flakyWriter) setFailing(v bool) {
	f.mu.Lock()
	f.fail = v
	f.mu.Unlock()
}

func (f *flakyWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return 0, errors.New("no space left on device")
	}
	f.ok++
	return len(p), nil
}

func TestAccessLogReportsItsOwnFailures(t *testing.T) {
	var diag bytes.Buffer
	lg, err := log.New(log.WithOutput(&diag), log.WithLevel(log.DEBUG))
	if err != nil {
		t.Fatal(err)
	}
	w := &flakyWriter{fail: true}
	sink := NewAccessLog("combined", lg, w)
	if sink == nil {
		t.Fatal("no sink")
	}

	record := Exchange{Client: "10.1.2.3", Method: "GET", Host: "example.com", Path: "/a", Status: 200}
	for i := 0; i < 50; i++ {
		sink(record)
	}
	out := diag.String()
	if !strings.Contains(out, "Access log records are being dropped") {
		t.Fatalf("a failing access log said nothing:\n%s", out)
	}
	// Rate-limited: a proxy under load writes thousands a second, and a
	// diagnostic per dropped record would take the other log down with it.
	if n := strings.Count(out, "Access log records are being dropped"); n != 1 {
		t.Errorf("50 failed writes produced %d diagnostics, want 1", n)
	}

	// Recovery is reported too, so the gap has both ends marked.
	w.setFailing(false)
	sink(record)
	out = diag.String()
	if !strings.Contains(out, "Access log writing again") {
		t.Errorf("recovery was not reported:\n%s", out)
	}
	if !strings.Contains(out, "records_lost") {
		t.Errorf("recovery did not say how many records were lost:\n%s", out)
	}
	if w.ok != 1 {
		t.Errorf("the writer took %d records after recovery, want 1", w.ok)
	}
}
