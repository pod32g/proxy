package server

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"

	log "github.com/pod32g/simple-logger"
)

// Router dispatches requests between the proxy handler and the UI handler.
type Router struct {
	Proxy   http.Handler
	UI      http.Handler
	API     http.Handler
	Metrics http.Handler

	// Auth reports the credentials to enforce, and is consulted on every
	// request so changes made through the UI or API take effect immediately.
	// A nil Auth disables authentication.
	Auth func() (enabled bool, username, password string)

	// Logger is optional and used only to warn about unusable auth settings.
	Logger *log.Logger

	warnOnce sync.Once
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// An absolute request URI means the client is asking the proxy to fetch a
	// remote resource; only origin-form requests are addressed to the proxy
	// itself. Everything below keys off that distinction — without it, any site
	// with a /ui/ or /api/ path becomes unproxyable and, worse, every client of
	// the proxy can reach the admin surface.
	direct := req.Method != http.MethodConnect && !req.URL.IsAbs()

	// Health checks answer before the auth gate so probes keep working when
	// credentials are set, and report only liveness.
	if direct && req.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	if !r.authOK(req) {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"proxy\"")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if direct {
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

func (r *Router) authOK(req *http.Request) bool {
	if r.Auth == nil {
		return true
	}
	enabled, username, password := r.Auth()
	if !enabled {
		return true
	}
	// Auth was asked for but cannot be enforced. Fail closed: passing traffic
	// through here would silently ignore the operator's intent, and the UI
	// would still report authentication as on.
	if username == "" || password == "" {
		r.warnOnce.Do(func() {
			if r.Logger != nil {
				r.Logger.Error("Authentication is enabled but the username or password is empty; refusing all requests")
			}
		})
		return false
	}

	user, pass, ok := req.BasicAuth()
	if !ok {
		user, pass, ok = proxyBasicAuth(req)
	}
	if !ok {
		return false
	}
	// Compare both halves unconditionally so the work — and the timing — does
	// not depend on how much of the credential the caller guessed correctly.
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(username))
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(password))
	return userOK&passOK == 1
}

// proxyBasicAuth reads credentials from Proxy-Authorization, the header a
// forward-proxy client is supposed to use, mirroring http.Request.BasicAuth.
func proxyBasicAuth(req *http.Request) (username, password string, ok bool) {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}
