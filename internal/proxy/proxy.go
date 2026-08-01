package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	log "github.com/pod32g/simple-logger"
)

func sanitizedURL(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.Path
}

// New creates a reverse proxy to the given target URL.
// The headers function receives the client address and returns headers to set on each upstream request.
func New(target *url.URL, logger *log.Logger, headers func(string) map[string]string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		logger.Debugf("Reverse proxy request %s %s", req.Method, sanitizedURL(req.URL))
		originalDirector(req)
		for k, v := range headers(clientIP(req.RemoteAddr)) {
			req.Header.Set(k, v)
		}
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		logger.Errorf("Upstream error: %v", err)
		http.Error(rw, "Bad gateway", http.StatusBadGateway)
	}

	return proxy
}
