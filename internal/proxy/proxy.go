package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/pod32g/proxy/internal/header"
	log "github.com/pod32g/simple-logger"
)

func sanitizedURL(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.Path
}

// New creates a reverse proxy to the given target URL.
// The headers function receives the client address and returns headers to set on each upstream request.
//
// upstreamTLS, when given, configures outbound TLS — a private trust bundle, a
// client certificate, or both. Reverse mode is where a private PKI upstream is
// most common, so it takes the same material forward mode does rather than
// being the one path that cannot reach an internal service.
func New(target *url.URL, logger *log.Logger, headers func(string) map[string]string,
	rules func(clientIP string) *header.RuleSet, upstreamTLS ...*tls.Config) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	if len(upstreamTLS) > 0 && upstreamTLS[0] != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = upstreamTLS[0].Clone()
		proxy.Transport = transport
	}
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		logger.Debugf("Reverse proxy request %s %s", req.Method, sanitizedURL(req.URL))
		originalDirector(req)
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
