package server

import "net"

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

// HostOnly is hostOnly for callers outside this package. The audit trail and
// the quota table key on an address, and they must all key on the same form of
// it or the same client looks like several.
func HostOnly(host string) string { return hostOnly(host) }

// Destinations used to be recorded here, on the way in. They are now recorded
// from the completion record, because recording before the handler runs counts
// requests the proxy went on to refuse — which let a client put entries in the
// "busiest destinations" view using requests that never succeeded. The
// middleware is gone rather than left unused so nobody wires it back.
