package server

import (
	"net/http"
	"time"

	log "github.com/pod32g/simple-logger"
)

// DebugMiddleware logs basic request details when enabled.
func DebugMiddleware(next http.Handler, logger *log.Logger, enabled func() bool) http.Handler {
	if next == nil || logger == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enabled != nil && !enabled() {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		dur := time.Since(start)
		if r.TLS == nil && r.URL.Scheme != "https" && r.Method != http.MethodConnect {
			logger.Debug("request", r.Method, sanitized(r), "status", rw.status, "dur", dur)
		}
	})
}

func sanitized(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + host + r.URL.Path
}
