package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/pod32g/proxy/internal/header"
	log "github.com/pod32g/simple-logger"
	"golang.org/x/net/http2"
)

func sanitizedURL(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.Path
}

// New creates a reverse proxy to the given target URL.
// The headers function receives the client address and returns headers to set on each upstream request.
//
// It takes the same Policy the forward path takes, and that is the point of the
// signature rather than an incidental tidy-up. Reverse mode used to receive
// four loose parameters, so every outbound setting had to be threaded here by
// hand — and three never were. A parent proxy, the HTTP/2 mode and the response
// cache were all silently inert in reverse mode while the startup log announced
// each of them as enabled. Taking the value both modes are configured from
// means a setting added to one cannot miss the other.
func New(target *url.URL, logger *log.Logger, headers func(string) map[string]string, pol Policy) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = pol.reverseTransport()

	rules := pol.HeaderRules
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		logger.Debugf("Reverse proxy request %s %s", req.Method, sanitizedURL(req.URL))
		originalDirector(req)
		// With a parent in front, the outbound Host has to name the target.
		//
		// ReverseProxy preserves the client's Host header, which is right for a
		// direct hop and lets a backend do virtual hosting. But net/http builds
		// a proxied request-line from Host, not from URL.Host — so preserving it
		// asks the parent to fetch from *this proxy's own address*, which is a
		// loop. The target's authority is what the parent must be told, and an
		// absolute-form request-target is authoritative over Host anyway
		// (RFC 7230 §5.4).
		//
		// Resolved per request, like every other use of the parent, so enabling
		// or clearing one takes effect without a restart.
		if pol.chained(target.Host) {
			req.Host = target.Host
		}
		for k, v := range headers(clientIP(req.RemoteAddr)) {
			req.Header.Set(k, v)
		}
		if rules != nil {
			rules(clientIP(req.RemoteAddr)).Apply(
				req.Header, header.Request, hostOnly(target.Host), nil)
		}
	}

	// Response rules run on the way back. PROXY-6's strip is the transport's
	// job here, and a rule that could re-add a hop-by-hop header is rejected
	// when it is written rather than filtered now.
	if rules != nil {
		proxy.ModifyResponse = func(resp *http.Response) error {
			rules(clientIP(resp.Request.RemoteAddr)).Apply(
				resp.Header, header.Response, hostOnly(target.Host), nil)
			return nil
		}
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		logger.Errorf("Upstream error: %v", err)
		http.Error(rw, "Bad gateway", http.StatusBadGateway)
	}

	return proxy
}

// reverseTransport builds the outbound round tripper for a fixed target.
//
// It goes through buildTransport, so the parent proxy hook, the HTTP/2 mode and
// the upstream TLS material are the same ones the forward path gets, built by
// the same code.
//
// The destination policy is deliberately not applied. That policy exists
// because a forward proxy takes destinations from untrusted clients; a reverse
// proxy has one target, chosen by the operator and named on the command line.
// Enforcing the private-address default against it would refuse the default
// configuration — `-target http://localhost:9000` — which is a check answering
// a question nobody asked.
func (p Policy) reverseTransport() http.RoundTripper {
	fixed := p
	fixed.Rules = nil
	fixed.AllowPrivate = true

	ordinary, _, h2 := fixed.buildTransport(fixed.dialer())
	return &reverseRoundTripper{pol: fixed, ordinary: ordinary, h2: h2}
}

// reverseRoundTripper picks between the ordinary and h2c transports per
// request, exactly as the forward handler does — including the rule that a
// request going through a parent must not use h2c, which dials origins itself
// and would bypass the parent.
type reverseRoundTripper struct {
	pol      Policy
	ordinary *http.Transport
	h2       *http2.Transport
}

func (t *reverseRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.pol.roundTripper(t.ordinary, t.h2, r).RoundTrip(r)
}
