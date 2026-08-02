package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2"
)

// UpstreamHTTP2 says how the proxy speaks HTTP/2 to origins.
type UpstreamHTTP2 string

const (
	// HTTP2Auto negotiates over TLS via ALPN and uses HTTP/1.1 in cleartext.
	// This is what Go's default transport already did, made explicit.
	HTTP2Auto UpstreamHTTP2 = "auto"
	// HTTP2Off forces HTTP/1.1 everywhere, for an origin whose HTTP/2 is
	// broken or a middlebox that mangles it.
	HTTP2Off UpstreamHTTP2 = "off"
	// HTTP2Cleartext speaks HTTP/2 without TLS — h2c — which is the common
	// shape for a reverse proxy sitting in front of a modern backend on a
	// trusted network.
	HTTP2Cleartext UpstreamHTTP2 = "h2c"
)

// UpstreamHTTP2Modes lists the accepted values.
var UpstreamHTTP2Modes = []string{string(HTTP2Auto), string(HTTP2Off), string(HTTP2Cleartext)}

// ParseUpstreamHTTP2 validates a mode. As with every other enum here, a typo is
// an error rather than a silent fallback: quietly speaking a different protocol
// to origins than the operator asked for is not something anyone would notice
// until it broke.
func ParseUpstreamHTTP2(mode string) (UpstreamHTTP2, error) {
	m := UpstreamHTTP2(strings.ToLower(strings.TrimSpace(mode)))
	switch m {
	case HTTP2Auto, HTTP2Off, HTTP2Cleartext:
		return m, nil
	case "":
		return HTTP2Auto, nil
	}
	return "", fmt.Errorf("invalid upstream HTTP/2 mode %q (want one of %s)",
		mode, strings.Join(UpstreamHTTP2Modes, ", "))
}

// buildTransport assembles the round tripper for a policy.
//
// Two are built, not one. The upgrade path needs HTTP/1.1 unconditionally —
// see upgradeTransport — so the h2 setting governs ordinary requests only.
func (p Policy) buildTransport(dialer *net.Dialer) (ordinary, upgrade *http.Transport, h2 *http2.Transport) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.DialContext = p.dialContext(dialer)
	if p.UpstreamTLS != nil {
		base.TLSClientConfig = p.UpstreamTLS.Clone()
	}
	// Resolved per request rather than at build time, so a reload that
	// repoints the parent reaches traffic already in flight through this
	// transport rather than only new processes.
	if p.Upstream != nil {
		base.Proxy = func(r *http.Request) (*url.URL, error) {
			parent := p.parent()
			if !parent.Configured() || parent.Bypass(r.URL.Host) {
				return nil, nil
			}
			return parent.URL, nil
		}
	}

	// The upgrade transport is a separate clone fixed at HTTP/1.1. Connection:
	// Upgrade does not exist in HTTP/2 — the mechanism was replaced by extended
	// CONNECT — so an upgrade issued over an h2 connection is rejected, and
	// PROXY-47 established that a broken upgrade comes back as an ordinary
	// response rather than an error. It would fail silently.
	upgrade = base.Clone()
	upgrade.ForceAttemptHTTP2 = false
	upgrade.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	upgrade.TLSClientConfig = withALPN(upgrade.TLSClientConfig, "http/1.1")

	switch p.HTTP2 {
	case HTTP2Off:
		// Three things, not one, and leaving any out fails in a way that looks
		// like an upstream fault:
		//
		//   ForceAttemptHTTP2 alone can reinstate h2;
		//   TLSNextProto alone leaves the ALPN offer in place;
		//   and the ALPN offer is the one that actually matters — a server that
		//   sees "h2" advertised will speak HTTP/2, and an HTTP/1.1 transport
		//   then tries to parse the HTTP/2 preface as a response and reports a
		//   malformed reply.
		//
		// The ALPN list is also inherited rather than empty: cloning
		// http.DefaultTransport picks up whatever has been configured on that
		// process-global value, so it has to be set rather than assumed.
		base.ForceAttemptHTTP2 = false
		base.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		base.TLSClientConfig = withALPN(base.TLSClientConfig, "http/1.1")
	case HTTP2Cleartext:
		// h2c has no negotiation: the client simply speaks HTTP/2 on a plain
		// connection because it was told the server does. That is why it is an
		// explicit setting rather than something that can be detected.
		h2 = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return p.dialContext(dialer)(ctx, network, addr)
			},
		}
	default:
		base.ForceAttemptHTTP2 = true
		base.TLSClientConfig = withALPN(base.TLSClientConfig, "h2", "http/1.1")
	}
	return base, upgrade, h2
}

// withALPN returns a TLS config advertising exactly the given protocols.
//
// Explicit rather than inherited. The base is a clone of
// http.DefaultTransport, a process-global that other code — httptest's
// StartTLS, for one — mutates, so whatever ALPN list it happens to carry is not
// something to build behaviour on.
func withALPN(cfg *tls.Config, protos ...string) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	cfg.NextProtos = protos
	return cfg
}

// roundTripper picks the transport for a request.
//
// With h2c configured, cleartext requests go over HTTP/2 and TLS ones keep
// negotiating normally — h2c is about the cleartext hop, and forcing it onto a
// TLS connection would skip the ALPN that already answers the question.
func (p Policy) roundTripper(ordinary *http.Transport, h2 *http2.Transport, r *http.Request) http.RoundTripper {
	if h2 != nil && r.URL.Scheme == "http" {
		return h2
	}
	return ordinary
}
