package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	log "github.com/pod32g/simple-logger"
)

// New creates a reverse proxy to the given target URL.
func New(target *url.URL, logger *log.Logger, headers map[string]string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		logger.Error("Upstream Error: %v", err)
		http.Error(rw, "Bad gateway", http.StatusBadGateway)
	}

	return proxy
}
