package server

import (
	"net"
	"net/http"
)

// hostOnly strips a trailing port. Splitting on the last colon by hand looks
// equivalent and is not: a bare IPv6 literal is all colons, so `2001:db8::1`
// would be recorded as `2001:db8:` and distinct addresses would collapse onto
// one bogus entry. SplitHostPort fails when there is no port, which is exactly
// when the input should be kept as-is.
func hostOnly(host string) string {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// StatsMiddleware records hosts for incoming requests using DomainStats.
func StatsMiddleware(next http.Handler, stats *DomainStats, enabled func() bool, hostGetter func(*http.Request) string) http.Handler {
	if next == nil || stats == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enabled == nil || enabled() {
			stats.Record(hostOnly(hostGetter(r)))
		}
		next.ServeHTTP(w, r)
	})
}
