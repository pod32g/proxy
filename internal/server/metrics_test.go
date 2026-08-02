package server

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsMiddleware(t *testing.T) {
	metrics := mustMetrics(t)
	handler := MetricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }), metrics)
	req := httptest.NewRequest("POST", "http://host/", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if code := rw.Result().StatusCode; code != 201 {
		t.Fatalf("status %d", code)
	}
	// The listener label is empty when nothing tagged the request, which is what
	// a single-listener deployment produces.
	if v := testutil.ToFloat64(metrics.Requests.WithLabelValues("POST", "201", "")); v != 1 {
		t.Fatalf("requests metric %f", v)
	}
}

// With several listeners up, the metric has to say which one served a request;
// otherwise the first question anyone asks of a multi-listener deployment is the
// one the metric cannot answer.
func TestMetricsRecordTheListener(t *testing.T) {
	metrics := mustMetrics(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	handler := WithListener(MetricsMiddleware(inner, metrics), "internal")

	req := httptest.NewRequest("GET", "http://host/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if v := testutil.ToFloat64(metrics.Requests.WithLabelValues("GET", "200", "internal")); v != 1 {
		t.Errorf("requests{listener=\"internal\"} = %f, want 1", v)
	}
	if v := testutil.ToFloat64(metrics.Requests.WithLabelValues("GET", "200", "")); v != 0 {
		t.Errorf("the request was also counted with no listener label: %f", v)
	}
}

func mustMetrics(t *testing.T) *Metrics {
	t.Helper()
	// A private registry per test: the collectors are process-global otherwise
	// and a second construction would panic.
	m, err := NewMetrics(prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A protocol switch is written to a hijacked connection, so the handler cannot
// report it through WriteHeader. Without SetStatus the exchange would be
// counted as a 200 and be indistinguishable from an ordinary request.
func TestMetricsRecordsProtocolSwitch(t *testing.T) {
	m := mustMetrics(t)
	h := MetricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(interface{ SetStatus(int) }).SetStatus(http.StatusSwitchingProtocols)
	}), m)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	if got := testutil.ToFloat64(m.Requests.WithLabelValues("GET", "101", "")); got != 1 {
		t.Errorf("101 not recorded: got %v", got)
	}
	if got := testutil.ToFloat64(m.Requests.WithLabelValues("GET", "200", "")); got != 0 {
		t.Errorf("switch was counted as a 200: got %v", got)
	}
}

// A handler that writes nothing at all still counts as a 200 — a hijacked
// CONNECT, for instance.
func TestMetricsDefaultsToOK(t *testing.T) {
	m := mustMetrics(t)
	h := MetricsMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), m)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if got := testutil.ToFloat64(m.Requests.WithLabelValues("GET", "200", "")); got != 1 {
		t.Errorf("got %v, want 1", got)
	}
}

// PROXY-85. Every wrapper between a handler and the layer that consumes a
// signal has to forward it, and statusRecorder forwarded SkipAccounting
// without Skipped. It worked only because MetricsMiddleware read the flag off
// the writer it was *given* rather than the one it created — so accounting
// happening to wrap metrics was load-bearing. Flip the order and every liveness
// probe lands in the request counter, silently and forever.
func TestSkipAccountingSurvivesEitherNestingOrder(t *testing.T) {
	skip := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s, ok := w.(interface{ SkipAccounting() }); ok {
			s.SkipAccounting()
		}
		w.WriteHeader(http.StatusOK)
	})

	for _, tc := range []struct {
		name  string
		build func(*Metrics, *int) http.Handler
	}{
		{"accounting outside metrics", func(m *Metrics, logged *int) http.Handler {
			return AccountingMiddleware(MetricsMiddleware(skip, m), Accounting{
				Completed: func(Exchange) { *logged++ },
			})
		}},
		{"metrics outside accounting", func(m *Metrics, logged *int) http.Handler {
			return MetricsMiddleware(AccountingMiddleware(skip, Accounting{
				Completed: func(Exchange) { *logged++ },
			}), m)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			m, err := NewMetrics(reg)
			if err != nil {
				t.Fatal(err)
			}
			logged := 0
			req := httptest.NewRequest("GET", "/healthz", nil)
			req.RemoteAddr = "10.1.2.3:5000"
			tc.build(m, &logged).ServeHTTP(httptest.NewRecorder(), req)

			if logged != 0 {
				t.Errorf("a skipped exchange reached the access log %d times", logged)
			}
			if n := countRequests(t, reg); n != 0 {
				t.Errorf("a skipped exchange was counted %v times in proxy_http_requests_total", n)
			}
		})
	}
}

func countRequests(t *testing.T, reg *prometheus.Registry) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, f := range families {
		if f.GetName() != "proxy_http_requests_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

// PROXY-86. The method is a client-chosen token and a metric vector never
// evicts, so every distinct value used to be a permanent series — minted before
// the Router had a chance to refuse the request.
func TestMadeUpMethodsDoNotGrowTheRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	h := MetricsMiddleware(okHandler("ok"), m)
	for i := 0; i < 500; i++ {
		req := httptest.NewRequest(fmt.Sprintf("BOGUS%d", i), "http://example.com/", nil)
		req.RemoteAddr = "10.1.2.3:5000"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	// One real method too, so the test would catch a fix that collapsed
	// everything to "other" rather than only the unrecognised.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	h.ServeHTTP(httptest.NewRecorder(), req)

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		switch f.GetName() {
		case "proxy_http_requests_total", "proxy_http_request_duration_seconds":
			if n := len(f.GetMetric()); n > 2 {
				t.Errorf("%s has %d series after 500 made-up methods, want 2", f.GetName(), n)
			}
			var seen []string
			for _, mm := range f.GetMetric() {
				for _, l := range mm.GetLabel() {
					if l.GetName() == "method" {
						seen = append(seen, l.GetValue())
					}
				}
			}
			t.Logf("%-42s method labels: %v", f.GetName(), seen)
		}
	}
}

func TestMethodLabelKeepsTheStandardSet(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"} {
		if got := MethodLabel(m); got != m {
			t.Errorf("MethodLabel(%q) = %q, want it unchanged", m, got)
		}
	}
	for _, m := range []string{"BOGUS", "get", "", "PROPFIND", strings.Repeat("A", 400)} {
		if got := MethodLabel(m); got != "other" {
			t.Errorf("MethodLabel(%q) = %q, want \"other\"", m, got)
		}
	}
}
