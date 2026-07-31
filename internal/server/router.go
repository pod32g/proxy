package server

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/pod32g/simple-logger"
	"github.com/prometheus/client_golang/prometheus"
)

// Failed credentials are cheap to retry over a network, so they are counted per
// source and throttled. The window is short enough that a legitimate operator
// who fat-fingers a password is not locked out for long, and long enough that
// guessing at any useful rate is not possible.
const (
	authFailureLimit  = 10
	authFailureWindow = time.Minute
)

// DefaultHealthPath is where the liveness endpoint lives unless configured
// otherwise.
const DefaultHealthPath = "/healthz"

// Router dispatches requests between the proxy handler and the UI handler.
type Router struct {
	Proxy   http.Handler
	UI      http.Handler
	API     http.Handler
	Metrics http.Handler

	// Auth reports the credentials to enforce, and is consulted on every
	// request so changes made through the UI or API take effect immediately.
	// A nil Auth disables authentication.
	Auth func() (enabled bool, username, password string)

	// HealthPath is answered without authentication. Empty disables it.
	// It is configurable because in reverse mode the proxy would otherwise
	// shadow a backend that serves the same path.
	HealthPath string

	// MetricsPublic exempts the metrics endpoint from authentication, so a
	// scraper that sends no credentials keeps working when auth is enabled.
	MetricsPublic bool

	// Logger and AuthFailures are optional.
	Logger       *log.Logger
	AuthFailures prometheus.Counter

	warnOnce sync.Once

	failMu   sync.Mutex
	failures map[string]*authFailure
}

type authFailure struct {
	count int
	first time.Time
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// An absolute request URI means the client is asking the proxy to fetch a
	// remote resource; only origin-form requests are addressed to the proxy
	// itself. Everything below keys off that distinction — without it, any site
	// with a /ui/ or /api/ path becomes unproxyable and, worse, every client of
	// the proxy can reach the admin surface.
	proxied := req.Method == http.MethodConnect || req.URL.IsAbs()
	direct := !proxied

	// Health checks answer before the auth gate so probes keep working when
	// credentials are set, and report only liveness.
	healthPath := r.HealthPath
	if direct && healthPath != "" && req.URL.Path == healthPath {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	metricsRequest := direct && r.Metrics != nil && req.URL.Path == "/metrics"
	if !(metricsRequest && r.MetricsPublic) {
		if ok, retryAfter := r.authOK(req); !ok {
			r.denyAuth(w, req, proxied, retryAfter)
			return
		}
	}

	if direct {
		if metricsRequest {
			r.Metrics.ServeHTTP(w, req)
			return
		}
		if r.API != nil && strings.HasPrefix(req.URL.Path, "/api/") {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/api")
			r.API.ServeHTTP(w, req)
			return
		}
		if r.UI != nil {
			if req.URL.Path == "/ui" {
				http.Redirect(w, req, "/ui/", http.StatusMovedPermanently)
				return
			}
			if strings.HasPrefix(req.URL.Path, "/ui/") {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, "/ui")
				r.UI.ServeHTTP(w, req)
				return
			}
		}
	}

	if r.Proxy != nil {
		r.Proxy.ServeHTTP(w, req)
	} else {
		http.NotFound(w, req)
	}
}

// denyAuth writes the challenge. A request the proxy was asked to *forward*
// needs 407 with Proxy-Authenticate (RFC 7235 §3.2); clients such as curl
// --proxy-user key their credential retry off that status and will not retry a
// 401. A request addressed to the proxy itself gets the ordinary 401.
func (r *Router) denyAuth(w http.ResponseWriter, req *http.Request, proxied bool, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		http.Error(w, "Too many failed authentication attempts", http.StatusTooManyRequests)
		return
	}
	if proxied {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="proxy"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// authOK reports whether the request may proceed, and how long the caller
// should wait if it is being throttled.
func (r *Router) authOK(req *http.Request) (bool, time.Duration) {
	if r.Auth == nil {
		return true, 0
	}
	enabled, username, password := r.Auth()
	if !enabled {
		return true, 0
	}
	// Auth was asked for but cannot be enforced. Fail closed: passing traffic
	// through here would silently ignore the operator's intent, and the UI
	// would still report authentication as on.
	if username == "" || password == "" {
		r.warnOnce.Do(func() {
			if r.Logger != nil {
				r.Logger.Error("Authentication is enabled but the username or password is empty; refusing all requests")
			}
		})
		return false, 0
	}

	source := hostOnly(req.RemoteAddr)
	if wait := r.throttled(source); wait > 0 {
		return false, wait
	}

	user, pass, ok := req.BasicAuth()
	if !ok {
		user, pass, ok = proxyBasicAuth(req)
	}
	if ok {
		// Compare both halves unconditionally so the work — and the timing —
		// does not depend on how much of the credential the caller guessed.
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(username))
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(password))
		if userOK&passOK == 1 {
			r.clearFailures(source)
			return true, 0
		}
	}
	r.recordFailure(source, ok)
	return false, 0
}

// throttled reports the remaining lockout for a source that has failed too often.
func (r *Router) throttled(source string) time.Duration {
	if source == "" {
		return 0
	}
	r.failMu.Lock()
	defer r.failMu.Unlock()
	f, ok := r.failures[source]
	if !ok {
		return 0
	}
	elapsed := time.Since(f.first)
	if elapsed >= authFailureWindow {
		delete(r.failures, source)
		return 0
	}
	if f.count < authFailureLimit {
		return 0
	}
	return authFailureWindow - elapsed
}

// recordFailure counts a rejected attempt and logs it. Silent failures leave no
// trace of a credential-guessing run anywhere in the proxy's own output.
func (r *Router) recordFailure(source string, hadCredentials bool) {
	if r.AuthFailures != nil {
		r.AuthFailures.Inc()
	}
	if source == "" {
		return
	}
	r.failMu.Lock()
	if r.failures == nil {
		r.failures = make(map[string]*authFailure)
	}
	f, ok := r.failures[source]
	if !ok || time.Since(f.first) >= authFailureWindow {
		f = &authFailure{first: time.Now()}
		r.failures[source] = f
	}
	f.count++
	count := f.count
	// Bound the table: a spray from many forged sources must not become its own
	// memory-growth problem.
	if len(r.failures) > 10000 {
		for k, v := range r.failures {
			if time.Since(v.first) >= authFailureWindow {
				delete(r.failures, k)
			}
		}
	}
	r.failMu.Unlock()

	if r.Logger != nil && hadCredentials {
		r.Logger.Warn("Rejected credentials from", source, "- failures in the last minute:", count)
	}
}

func (r *Router) clearFailures(source string) {
	if source == "" {
		return
	}
	r.failMu.Lock()
	delete(r.failures, source)
	r.failMu.Unlock()
}

// proxyBasicAuth reads credentials from Proxy-Authorization, the header a
// forward-proxy client is supposed to use, mirroring http.Request.BasicAuth.
func proxyBasicAuth(req *http.Request) (username, password string, ok bool) {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}
