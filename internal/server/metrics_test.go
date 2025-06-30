package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsMiddleware(t *testing.T) {
	metrics := NewMetrics()
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
