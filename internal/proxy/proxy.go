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
func New(target *url.URL, logger *log.Logger, headers func(string) map[string]string, ultra func() bool) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		logger.Debug("Reverse proxy request", req.Method, sanitizedURL(req.URL))
		if ultra != nil && ultra() {
			if dump, err := httputil.DumpRequest(req, true); err == nil {
				logger.Debug("reverse request dump\n" + string(dump))
			}
		}
		originalDirector(req)
		hdrs := headers(req.RemoteAddr)
		viaVal := hdrs["Via"]
		if viaVal == "" {
			viaVal = "1.1 go-proxy"
		}
		addProxyHeaders(req, req.RemoteAddr, viaVal)
		for k, v := range hdrs {
			if k == "Via" {
				continue
			}
			req.Header.Set(k, v)
		}
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		logger.Error("Upstream Error: %v", err)
		http.Error(rw, "Bad gateway", http.StatusBadGateway)
	}

	return proxy
}
