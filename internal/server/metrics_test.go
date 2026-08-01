package server

import (
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
	if v := testutil.ToFloat64(metrics.Requests.WithLabelValues("POST", "201")); v != 1 {
		t.Fatalf("requests metric %f", v)
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

	if got := testutil.ToFloat64(m.Requests.WithLabelValues("GET", "101")); got != 1 {
		t.Errorf("101 not recorded: got %v", got)
	}
	if got := testutil.ToFloat64(m.Requests.WithLabelValues("GET", "200")); got != 0 {
		t.Errorf("switch was counted as a 200: got %v", got)
	}
}

// A handler that writes nothing at all still counts as a 200 — a hijacked
// CONNECT, for instance.
func TestMetricsDefaultsToOK(t *testing.T) {
	m := mustMetrics(t)
	h := MetricsMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), m)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if got := testutil.ToFloat64(m.Requests.WithLabelValues("GET", "200")); got != 1 {
		t.Errorf("got %v, want 1", got)
	}
}
