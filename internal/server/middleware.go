package server

import (
	"net/http"
	"strings"
)

// StatsMiddleware records hosts for incoming requests using DomainStats.
func StatsMiddleware(next http.Handler, stats *DomainStats, enabled func() bool, hostGetter func(*http.Request) string) http.Handler {
	if next == nil || stats == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enabled == nil || enabled() {
			host := hostGetter(r)
			if host != "" {
				if i := strings.LastIndex(host, ":"); i >= 0 {
					host = host[:i]
				}
				stats.Record(host)
			}
		}
		next.ServeHTTP(w, r)
	})
}
