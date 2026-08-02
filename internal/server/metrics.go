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
	// exhaustion is visible before anyone hits it. Labelled by direction:
	// "in" is from the client, "out" is to it.
	RelayedBytes *prometheus.CounterVec
	// QuotaClients is the size of the per-client bucket table, which is bounded
	// and therefore worth watching for eviction pressure.
	QuotaClients prometheus.Gauge

	// UpstreamDuration is how long the origin took, as distinct from how long
	// the client waited. The existing duration histogram measures the whole
	// exchange, so a slow origin and a slow proxy look identical in it — which
	// is the question anyone actually has when latency rises.
	UpstreamDuration *prometheus.HistogramVec
	// ActiveTunnels counts established CONNECT tunnels. They are long-lived and
	// invisible to a request counter, which sees each one exactly once.
	ActiveTunnels prometheus.Gauge
	// UpstreamProtocol counts round trips by the protocol actually negotiated
	// with the origin. Two values in practice, so no cardinality risk — and
	// before this there was no way to tell what had been spoken at all.
	UpstreamProtocol *prometheus.CounterVec
	// CacheEvents counts hits, misses, revalidations, stores and evictions.
	// A cache whose hit rate cannot be seen is one nobody can tell is working.
	CacheEvents *prometheus.CounterVec
	// CacheBytes and CacheEntries are current occupancy, so the bound is
	// observable rather than merely promised.
	CacheBytes   prometheus.Gauge
	CacheEntries prometheus.Gauge
	// PolicyDecisions counts refusals by what refused them, so a spike is
	// attributable without reading logs. Both labels are closed sets.
	PolicyDecisions *prometheus.CounterVec
}

// The values PolicyDecisions takes for its "scope" label are proxy.DeniedScope,
// declared where the refusals are made. They were also declared here once, as a
// second closed set that nothing referenced — so this package documented a
// cardinality guarantee it had no part in enforcing. One declaration, in the
// package that produces the values.

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
			// The listener label is bounded by the number of configured
			// listeners, so it carries no cardinality risk, and it is the only
			// way to tell which interface served a request when several are up.
			[]string{"method", "code", "listener"},
		),
		Duration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "proxy_http_request_duration_seconds",
				Help:    "Duration of HTTP requests",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "listener"},
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
		RelayedBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_relayed_bytes_total",
				Help: "Total bytes relayed on behalf of clients, by direction",
			},
			[]string{"direction"},
		),
		QuotaClients: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "proxy_quota_tracked_clients",
				Help: "Number of clients with live quota buckets",
			},
		),
		UpstreamDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "proxy_upstream_duration_seconds",
				Help:    "Time the upstream took to respond, excluding proxy-side work",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),
		ActiveTunnels: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "proxy_active_tunnels",
				Help: "Number of established CONNECT tunnels",
			},
		),
		UpstreamProtocol: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_upstream_protocol_total",
				Help: "Upstream round trips by the protocol negotiated with the origin",
			},
			[]string{"proto"},
		),
		CacheEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_cache_events_total",
				Help: "Response cache events by kind: hit, miss, revalidated, stored, evicted",
			},
			[]string{"event"},
		),
		CacheBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "proxy_cache_bytes",
			Help: "Bytes currently held in the response cache",
		}),
		CacheEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "proxy_cache_entries",
			Help: "Responses currently held in the cache",
		}),
		PolicyDecisions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_policy_decisions_total",
				Help: "Requests refused by destination policy, by what refused them",
			},
			[]string{"scope"},
		),
	}
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	for _, c := range []prometheus.Collector{
		m.Requests, m.Duration, m.Clients, m.AuthFailures,
		m.QuotaRejected, m.RelayedBytes, m.QuotaClients,
		m.UpstreamDuration, m.ActiveTunnels, m.PolicyDecisions, m.UpstreamProtocol,
		m.CacheEvents, m.CacheBytes, m.CacheEntries,
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

		// Liveness probes and the admin surface are not proxy traffic, and
		// counting them would put a constant floor under every request-rate
		// graph and make "requests to the proxy" mean two different things.
		//
		// Read from rec, the writer this middleware created, like every other
		// signal here. It used to read from w, which worked only because
		// accounting happens to wrap metrics: with the nesting the other way w
		// is the bare ResponseWriter, the assertion fails, and every probe
		// lands in the counter. That is the failure SkipAccounting exists to
		// prevent, reintroduced by the order two middlewares are composed in.
		if rec.Skipped() {
			return
		}
		dur := time.Since(start).Seconds()
		// status stays 0 when the handler neither wrote nor set a code — a
		// hijacked CONNECT, for instance. That is a 200 as far as the client
		// is concerned.
		code := rec.status
		if code == 0 {
			code = http.StatusOK
		}
		name := ListenerName(r.Context())
		m.Duration.WithLabelValues(r.Method, name).Observe(dur)
		m.Requests.WithLabelValues(r.Method, strconv.Itoa(code), name).Inc()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	skipped bool
}

// SetStatus records a status the handler could not report through WriteHeader.
// A protocol switch is written directly to a hijacked connection, so without
// this the exchange would be counted as a 200 like any other.
func (r *statusRecorder) SetStatus(code int) { r.status = code }

// SetProtocol passes the negotiated protocol down to the accounting layer.
func (r *statusRecorder) SetProtocol(proto string) {
	if s, ok := r.ResponseWriter.(interface{ SetProtocol(string) }); ok {
		s.SetProtocol(proto)
	}
}

// SkipAccounting passes the exclusion signal down to the accounting layer.
func (r *statusRecorder) SkipAccounting() {
	r.skipped = true
	if s, ok := r.ResponseWriter.(interface{ SkipAccounting() }); ok {
		s.SkipAccounting()
	}
}

// Skipped reports whether this exchange was excluded, by this layer or by any
// below it.
//
// Both halves are needed. A handler may call SkipAccounting on this writer, and
// an outer layer may already have been told; forwarding the setter without the
// getter left this wrapper unable to answer a question it had been asked.
func (r *statusRecorder) Skipped() bool {
	if r.skipped {
		return true
	}
	s, ok := r.ResponseWriter.(interface{ Skipped() bool })
	return ok && s.Skipped()
}

// SetServed passes the handler's "this reached a destination" signal down to
// the accounting layer, which is what consumes it.
//
// Every wrapper between the handler and the layer that cares has to forward
// this, or the signal is silently swallowed by whichever one does not — which
// is exactly what happened here the first time: the unit tests passed against a
// bare writer while the assembled stack dropped it.
func (r *statusRecorder) SetServed() {
	if s, ok := r.ResponseWriter.(interface{ SetServed() }); ok {
		s.SetServed()
	}
}

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
