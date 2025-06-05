package server

import (
	"net/http"
	"strings"
)

// Router dispatches requests between the proxy handler and the UI handler.
type Router struct {
	Proxy http.Handler
	UI    http.Handler
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// CONNECT requests never have a path starting with '/'
	if req.Method != http.MethodConnect && r.UI != nil {
		if req.URL.Path == "/ui" {
			http.Redirect(w, req, "/ui/", http.StatusMovedPermanently)
			return
		}
		if strings.HasPrefix(req.URL.Path, "/ui/") {
			// strip prefix as ServeMux would do
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/ui")
			r.UI.ServeHTTP(w, req)
			return
		}
	}
	if r.Proxy != nil {
		r.Proxy.ServeHTTP(w, req)
	} else {
		http.NotFound(w, req)
	}
}
