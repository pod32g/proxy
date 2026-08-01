// Package reqid assigns an identifier to each request so one exchange can be
// followed across the proxy hop, from the client's logs through ours to the
// origin's.
//
// It lives in its own package because the middleware that assigns an ID and the
// handler that forwards it upstream are in different packages, and neither
// should have to import the other to agree on a header name.
package reqid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// Header is the header carrying the identifier. X-Request-Id is not a standard,
// but it is what proxies, load balancers and application frameworks have
// converged on, and interoperating with what exists beats being correct alone.
const Header = "X-Request-Id"

// MaxLength bounds an inbound identifier. Generous enough for a UUID, a ULID or
// a W3C trace-id, small enough that it cannot bloat every log line for the
// request.
const MaxLength = 128

type ctxKey struct{}

// New returns a fresh identifier: 16 random bytes, hex encoded.
//
// That is deliberately the shape of a W3C trace-id, so that when tracing is
// enabled the request ID and the trace ID can be the same value rather than two
// identifiers somebody has to join by timestamp.
func New() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Getting here means the system entropy source failed, which is not a
		// reason to drop a request. An empty ID reads as "not identified",
		// which is honest, and every caller already handles it.
		return ""
	}
	return hex.EncodeToString(buf[:])
}

// Sanitize returns an inbound identifier if it is usable, or "" if it is not.
//
// An inbound ID is honoured — that is the point — but not verbatim. The value
// is attacker-controlled and is about to be written into every log line for the
// request, so a newline in it could forge log records and a very long one could
// bloat every entry. Honouring garbage is not the same as honouring the caller.
func Sanitize(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > MaxLength {
		return ""
	}
	for _, r := range v {
		// Printable ASCII only, and no space or quote: those are field
		// separators in the log formats this ends up in.
		if r < '!' || r > '~' || r == '"' || r == '\\' {
			return ""
		}
	}
	return v
}

// FromRequestOrNew returns the caller's identifier when it sent a usable one,
// and a fresh one otherwise.
func FromRequestOrNew(header string) string {
	if id := Sanitize(header); id != "" {
		return id
	}
	return New()
}

// WithID attaches an identifier to a context.
func WithID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identifier attached to a context, or "".
func FromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}
