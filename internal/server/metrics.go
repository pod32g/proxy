package server

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	Requests     *prometheus.CounterVec
	Duration     *prometheus.HistogramVec
	Clients      prometheus.Gauge
	AuthFailures prometheus.Counter

	// QuotaRejected is labelled by which allowance ran out, so a single noisy
	// client is distinguishable from a proxy at its global ceiling. Without the
	// label the first thing anyone would ask on seeing the counter rise is
	// exactly the thing it could not answer.
	QuotaRejected *prometheus.CounterVec
	// RelayedBytes is what the byte quota is charged against, exported so
	// exhaustion is visible before anyone hits it.
	RelayedBytes prometheus.Counter
	// QuotaClients is the size of the per-client bucket table, which is bounded
	// and therefore worth watching for eviction pressure.
	QuotaClients prometheus.Gauge
}

// NewMetrics builds the collectors and registers them with reg. Taking a
// registerer rather than reaching for the global default means a second
// instance — a test, or two proxies in one process — gets its own registry
// instead of panicking on duplicate registration.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		Requests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_http_requests_total",
				Help: "Total number of HTTP requests processed",
			},
			[]string{"method", "code"},
		),
		Duration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "proxy_http_request_duration_seconds",
				Help:    "Duration of HTTP requests",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),
		Clients: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "proxy_active_clients",
				Help: "Number of active client connections",
			},
		),
		AuthFailures: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "proxy_auth_failures_total",
				Help: "Total number of rejected authentication attempts",
			},
		),
		QuotaRejected: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_quota_rejected_total",
				Help: "Total number of requests refused for exceeding a quota",
			},
			[]string{"scope"},
		),
		RelayedBytes: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "proxy_relayed_bytes_total",
				Help: "Total bytes relayed on behalf of clients, in both directions",
			},
		),
		QuotaClients: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "proxy_quota_tracked_clients",
				Help: "Number of clients with live quota buckets",
			},
		),
	}
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	for _, c := range []prometheus.Collector{
		m.Requests, m.Duration, m.Clients, m.AuthFailures,
		m.QuotaRejected, m.RelayedBytes, m.QuotaClients,
	} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// MetricsMiddleware records Prometheus metrics for requests.
func MetricsMiddleware(next http.Handler, m *Metrics) http.Handler {
	if next == nil || m == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(rec, r)
		dur := time.Since(start).Seconds()
		// status stays 0 when the handler neither wrote nor set a code — a
		// hijacked CONNECT, for instance. That is a 200 as far as the client
		// is concerned.
		code := rec.status
		if code == 0 {
			code = http.StatusOK
		}
		m.Duration.WithLabelValues(r.Method).Observe(dur)
		m.Requests.WithLabelValues(r.Method, strconv.Itoa(code)).Inc()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

// SetStatus records a status the handler could not report through WriteHeader.
// A protocol switch is written directly to a hijacked connection, so without
// this the exchange would be counted as a 200 like any other.
func (r *statusRecorder) SetStatus(code int) { r.status = code }

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		// no WriteHeader call yet, so it’s implicitly 200
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Hijack lets CONNECT handlers take over the connection
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support Hijacker")
	}
	return hj.Hijack()
}

// Flush allows callers to flush buffered data (e.g. for streaming)
func (r *statusRecorder) Flush() {
	if fl, ok := r.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// Push enables HTTP/2 server push
func (r *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := r.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
