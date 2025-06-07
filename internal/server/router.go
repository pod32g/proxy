package server

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// Router dispatches requests between the proxy handler and the UI handler.
type Router struct {
	Proxy       http.Handler
	UI          http.Handler
	API         http.Handler
	Metrics     http.Handler
	AuthEnabled bool
	Username    string
	Password    string
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.AuthEnabled && r.Username != "" {
		if !authOK(r, req) {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"proxy\"")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	// CONNECT requests never have a path starting with '/'
	if req.Method != http.MethodConnect {
		if r.Metrics != nil && req.URL.Path == "/metrics" {
			r.Metrics.ServeHTTP(w, req)
			return
		}
		if r.API != nil && strings.HasPrefix(req.URL.Path, "/api/") {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/api")
			r.API.ServeHTTP(w, req)
			return
		}
		if r.UI != nil {
			if req.URL.Path == "/ui" {
				http.Redirect(w, req, "/ui/", http.StatusMovedPermanently)
				return
			}
			if strings.HasPrefix(req.URL.Path, "/ui/") {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, "/ui")
				r.UI.ServeHTTP(w, req)
				return
			}
		}
	}
	if r.Proxy != nil {
		r.Proxy.ServeHTTP(w, req)
	} else {
		http.NotFound(w, req)
	}
}

func authOK(r *Router, req *http.Request) bool {
	user, pass, ok := req.BasicAuth()
	if ok && user == r.Username && pass == r.Password {
		return true
	}
	if auth := req.Header.Get("Proxy-Authorization"); auth != "" {
		if strings.HasPrefix(strings.ToLower(auth), "basic ") {
			b64 := strings.TrimSpace(auth[len("Basic "):])
			data, err := base64.StdEncoding.DecodeString(b64)
			if err == nil {
				parts := strings.SplitN(string(data), ":", 2)
				if len(parts) == 2 && parts[0] == r.Username && parts[1] == r.Password {
					return true
				}
			}
		}
	}
	return false
}
