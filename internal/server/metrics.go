package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

var (
	requestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total number of processed requests",
		},
		[]string{"method", "code"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "proxy_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "code"},
	)
	activeClients = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "proxy_active_clients",
			Help: "Number of active client connections",
		},
	)
)

func init() {
	prometheus.MustRegister(requestTotal, requestDuration, activeClients)
}

// MetricsHandler returns an HTTP handler exposing Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// MetricsMiddleware records metrics for all requests.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		RecordRequest(r.Method, rw.status, time.Since(start))
	})
}

// RecordRequest records metrics for a request with the given method and status code.
func RecordRequest(method string, code int, duration time.Duration) {
	c := fmt.Sprintf("%d", code)
	requestTotal.WithLabelValues(method, c).Inc()
	requestDuration.WithLabelValues(method, c).Observe(duration.Seconds())
}

// SetActiveClients sets the current active clients gauge.
func SetActiveClients(n int) {
	activeClients.Set(float64(n))
}
