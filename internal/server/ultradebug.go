package server

import (
	"net/http"
	"net/http/httputil"

	log "github.com/pod32g/simple-logger"
)

// UltraDebugMiddleware logs full request details when enabled.
func UltraDebugMiddleware(next http.Handler, logger *log.Logger, enabled func() bool) http.Handler {
	if next == nil || logger == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enabled != nil && !enabled() {
			next.ServeHTTP(w, r)
			return
		}
		// Skip ultra debug logging for HTTPS and CONNECT requests.
		if r.TLS == nil && r.Method != http.MethodConnect && r.URL.Scheme != "https" {
			if dump, err := httputil.DumpRequest(r, true); err == nil {
				logger.Debug("full request\n" + string(dump))
			} else {
				logger.Debug("dump request error", err)
			}
		}
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		logger.Debug("response status", rw.status)
	})
}
