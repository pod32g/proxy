// Package cache is a shared response cache for the proxy: an RFC 9111 subset,
// in memory, bounded by bytes.
//
// The rule everything here is arranged around is that a cache serving one
// user's content to another is not a degraded cache — it is a data breach with
// a performance benefit. So storability is decided by a deny-first gate that
// runs before any other consideration, and each of its rules is separable and
// separately tested.
package cache

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Cacheable status codes. The set RFC 9111 §3 calls heuristically cacheable,
// which is the set an origin may reasonably expect a shared cache to hold.
var cacheableStatus = map[int]bool{
	200: true, 203: true, 204: true, 300: true, 301: true,
	404: true, 405: true, 410: true, 414: true, 501: true,
}

// Reason names why something was not cached, for metrics and for the operator
// asking why their hit rate is zero.
type Reason string

const (
	ReasonStorable       Reason = ""
	ReasonMethod         Reason = "method"
	ReasonStatus         Reason = "status"
	ReasonNoStore        Reason = "no-store"
	ReasonPrivate        Reason = "private"
	ReasonAuthorization  Reason = "authorization"
	ReasonCookie         Reason = "cookie"
	ReasonSetCookie      Reason = "set-cookie"
	ReasonVaryAll        Reason = "vary-*"
	ReasonNoFreshness    Reason = "no-explicit-freshness"
	ReasonTooLarge       Reason = "too-large"
	ReasonRequestNoStore Reason = "request-no-store"
)

// StorableRequest reports whether a request may produce a cache entry.
//
// One rule, applied twice: a request that identifies a user does not produce a
// shared cache entry. Authorization, Proxy-Authorization and Cookie all
// identify a user, so all three are refused.
//
// This is stricter than RFC 9111 requires, deliberately and in both cases. The
// RFC permits caching an authenticated response when the origin says public,
// s-maxage or must-revalidate, and permits caching a response to a cookie-
// bearing request whenever the origin has not said otherwise. Both defences
// amount to "the origin should have told us" — and a shared forward proxy is
// exactly where an origin's omission becomes one user being served another's
// data. The upside on offer is a cache hit.
func StorableRequest(r *http.Request) Reason {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return ReasonMethod
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
		return ReasonAuthorization
	}
	if r.Header.Get("Cookie") != "" {
		return ReasonCookie
	}
	if directives(r.Header.Get("Cache-Control")).has("no-store") {
		return ReasonRequestNoStore
	}
	return ReasonStorable
}

// RequestWantsRevalidation reports whether a client demanded a fresh check.
//
// A client sending no-cache is asking to be told the entity is still current,
// not to be handed whatever the proxy happens to hold. Serving it a stored copy
// answers a question it did not ask.
func RequestWantsRevalidation(r *http.Request) bool {
	return directives(r.Header.Get("Cache-Control")).has("no-cache")
}

// StorableResponse reports whether a response may be stored. now is the clock,
// passed in rather than read, so the whole package answers to one.
func StorableResponse(resp *http.Response, now time.Time) Reason {
	if !cacheableStatus[resp.StatusCode] {
		return ReasonStatus
	}

	cc := directives(resp.Header.Get("Cache-Control"))
	switch {
	case cc.has("no-store"):
		return ReasonNoStore
	case cc.has("private"):
		// "private" means a single user's cache may hold this. A forward proxy
		// is shared by definition, so this is a refusal, not a hint.
		return ReasonPrivate
	}
	if resp.Header.Get("Set-Cookie") != "" {
		// A stored Set-Cookie would be replayed to whoever gets the hit,
		// handing them a session that is not theirs.
		return ReasonSetCookie
	}
	if strings.TrimSpace(resp.Header.Get("Vary")) == "*" {
		// Vary: * means the response depends on something not in the request
		// headers at all, so no stored entry can be known to match.
		return ReasonVaryAll
	}
	if _, ok := freshness(resp, cc, now); !ok {
		// Explicit freshness only. Heuristics from Last-Modified would have the
		// proxy invent a lifetime for content nobody labelled, and start
		// serving stale pages the origin never authorised.
		return ReasonNoFreshness
	}
	return ReasonStorable
}

// InitialAge is how old a response already was when it arrived (RFC 9111 §4.2.3).
//
// A forward proxy very often sits in front of a CDN or another cache, so this is
// the common case rather than the exotic one. Without it, a response arriving
// with "max-age=3600, Age: 3500" — a hundred seconds of life left — was stored
// for a further 3600, and served at up to twice the staleness the origin
// authorised. The origin's control over its own content quietly stopped meaning
// what it said.
//
// Both sources are consulted and the larger wins, as the RFC requires: Age can
// be missing from a cache that should have sent it, and Date can be skewed.
func InitialAge(h http.Header, now time.Time) time.Duration {
	var age time.Duration
	if v := h.Get("Age"); v != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
			age = time.Duration(secs) * time.Second
		}
	}
	if d := h.Get("Date"); d != "" {
		if sent, err := http.ParseTime(d); err == nil {
			// Negative when the origin's clock runs ahead of ours, which is not
			// a reason to treat a response as fresher than it is.
			if elapsed := now.Sub(sent); elapsed > age {
				age = elapsed
			}
		}
	}
	if age < 0 {
		return 0
	}
	return age
}

// freshness returns how long a response may be served without revalidation.
//
// This is the lifetime the origin declared, measured from when the origin
// generated the response — not from now. Subtracting the age it arrived with is
// the caller's job, because only the caller knows when "now" is. See InitialAge.
func freshness(resp *http.Response, cc directiveSet, now time.Time) (time.Duration, bool) {
	// s-maxage is addressed to shared caches specifically and wins over maxage.
	if v, ok := cc.value("s-maxage"); ok {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	if v, ok := cc.value("max-age"); ok {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	if exp := resp.Header.Get("Expires"); exp != "" {
		expires, err := http.ParseTime(exp)
		if err != nil {
			// An unparseable Expires means "already expired" per RFC 9111, not
			// "no opinion" — which is a refusal to store, not a long life.
			return 0, false
		}
		base := now
		if d := resp.Header.Get("Date"); d != "" {
			if parsed, err := http.ParseTime(d); err == nil {
				base = parsed
			}
		}
		if ttl := expires.Sub(base); ttl > 0 {
			return ttl, true
		}
		return 0, false
	}
	return 0, false
}

// Validator reports whether a response carries something to revalidate with.
// Without one, an expired entry is worthless and is simply dropped.
func Validator(h http.Header) (etag, lastModified string, ok bool) {
	etag = h.Get("ETag")
	lastModified = h.Get("Last-Modified")
	return etag, lastModified, etag != "" || lastModified != ""
}

// directiveSet is a parsed Cache-Control header.
type directiveSet map[string]string

func directives(header string) directiveSet {
	out := directiveSet{}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		out[strings.ToLower(strings.TrimSpace(name))] =
			strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out
}

func (d directiveSet) has(name string) bool {
	_, ok := d[name]
	return ok
}

func (d directiveSet) value(name string) (string, bool) {
	v, ok := d[name]
	return v, ok
}

// normaliseVaryNames renders a Vary header as a stable, comparable list, so the
// same set written two ways counts as one form in the candidate set.
func normaliseVaryNames(vary string) string {
	var names []string
	for _, name := range strings.Split(vary, ",") {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" && name != "*" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// varyKey renders the request headers a stored entry varies on, so a variant is
// only served to a request that matches it.
//
// Without this a cache keyed on the URL alone would serve a gzip-encoded body
// to a client that cannot decode it, or an English page to a client that asked
// for Japanese.
func varyKey(vary string, reqHeaders http.Header) string {
	if strings.TrimSpace(vary) == "" {
		return ""
	}
	var b strings.Builder
	// Sorted, so "Accept-Encoding, Accept-Language" and the reverse produce the
	// same fingerprint and therefore the same cache key.
	for _, name := range strings.Split(normaliseVaryNames(vary), ",") {
		if name == "" {
			continue
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(reqHeaders.Get(name))
		b.WriteByte('\n')
	}
	return b.String()
}
