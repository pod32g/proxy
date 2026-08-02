package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func staticAuth(enabled bool, user, pass string) func() (bool, string, string) {
	return func() (bool, string, string) { return enabled, user, pass }
}

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
}

func TestRouterAuth(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, "user", "pass")}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.SetBasicAuth("user", "pass")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}

	cred := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("Proxy-Authorization", "Basic "+cred)
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec3.Code)
	}

	// Right user, wrong password must not pass.
	req4 := httptest.NewRequest("GET", "/", nil)
	req4.SetBasicAuth("user", "wrong")
	rec4 := httptest.NewRecorder()
	r.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bad password, got %d", rec4.Code)
	}
}

func TestRouterAuthDisabled(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(false, "user", "pass")}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// Auth is consulted per request, so credentials changed at runtime take effect
// without a restart and a revoked password stops working immediately.
func TestRouterAuthIsLive(t *testing.T) {
	user, pass := "alice", "s3cret"
	r := &Router{
		Proxy: okHandler("proxied"),
		Auth:  func() (bool, string, string) { return true, user, pass },
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("alice", "s3cret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the original password to work, got %d", rec.Code)
	}

	pass = "rotated"

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.SetBasicAuth("alice", "s3cret")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("revoked password still accepted: got %d", rec2.Code)
	}

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.SetBasicAuth("alice", "rotated")
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("rotated password rejected: got %d", rec3.Code)
	}
}

// Enabling auth without usable credentials must deny, not wave everything through.
func TestRouterAuthFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, user, pass string }{
		{"empty username", "", "s3cret"},
		{"empty password", "alice", ""},
		{"both empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, tc.user, tc.pass)}
			req := httptest.NewRequest("GET", "/", nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", rec.Code)
			}
			// Supplying the partial credential must not help either.
			req2 := httptest.NewRequest("GET", "/", nil)
			req2.SetBasicAuth(tc.user, tc.pass)
			rec2 := httptest.NewRecorder()
			r.ServeHTTP(rec2, req2)
			if rec2.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 with partial credentials, got %d", rec2.Code)
			}
		})
	}
}

// A proxy client asking for a remote URL must be proxied, even when that URL's
// path collides with the admin surface.
func TestAdminSurfaceNotReachableThroughProxy(t *testing.T) {
	r := &Router{
		Proxy:      okHandler("PROXIED"),
		API:        okHandler("ADMIN-API"),
		UI:         okHandler("ADMIN-UI"),
		Metrics:    okHandler("ADMIN-METRICS"),
		HealthPath: DefaultHealthPath,
	}
	for _, target := range []string{
		"http://example.com/api/headers",
		"http://example.com/ui/general",
		"http://example.com/ui",
		"http://example.com/metrics",
		"http://example.com/healthz",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if got := rec.Body.String(); got != "PROXIED" {
			t.Errorf("%s: expected the request to be proxied, got %q", target, got)
		}
	}
}

// Addressed directly, the same paths still serve the admin surface.
func TestAdminSurfaceReachableDirectly(t *testing.T) {
	r := &Router{
		Proxy:   okHandler("PROXIED"),
		API:     okHandler("ADMIN-API"),
		UI:      okHandler("ADMIN-UI"),
		Metrics: okHandler("ADMIN-METRICS"),
	}
	for _, tc := range []struct{ path, want string }{
		{"/api/headers", "ADMIN-API"},
		{"/ui/general", "ADMIN-UI"},
		{"/metrics", "ADMIN-METRICS"},
		{"/anything-else", "PROXIED"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if got := rec.Body.String(); got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.path, tc.want, got)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("/ui should redirect, got %d", rec.Code)
	}
}

// Probes must work without credentials; nothing else may.
func TestHealthzBypassesAuth(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, "user", "pass"), HealthPath: DefaultHealthPath}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("healthz: got %d %q", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("healthz exemption leaked to other paths: got %d", rec2.Code)
	}
}

func TestProxyBasicAuthParsing(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		user, pass   string
		ok           bool
	}{
		{"valid", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p")), "u", "p", true},
		{"lowercase scheme", "basic " + base64.StdEncoding.EncodeToString([]byte("u:p")), "u", "p", true},
		{"password with colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p:q")), "u", "p:q", true},
		{"empty", "", "", "", false},
		{"not base64", "Basic !!!!", "", "", false},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), "", "", false},
		{"wrong scheme", "Bearer abc", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				req.Header.Set("Proxy-Authorization", tc.header)
			}
			user, pass, ok := proxyBasicAuth(req)
			if ok != tc.ok || user != tc.user || pass != tc.pass {
				t.Fatalf("got (%q, %q, %v), want (%q, %q, %v)", user, pass, ok, tc.user, tc.pass, tc.ok)
			}
		})
	}
}

// A request the proxy was asked to forward needs 407, not 401: curl
// --proxy-user and most HTTP libraries only retry with Proxy-Authorization
// when they see 407.
func TestProxiedRequestGets407(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, "u", "p")}

	proxied := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, proxied)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Errorf("proxied: got %d, want 407", rec.Code)
	}
	if rec.Header().Get("Proxy-Authenticate") == "" {
		t.Error("proxied: missing Proxy-Authenticate")
	}

	// A request addressed to the proxy itself still gets the ordinary 401.
	direct := httptest.NewRequest(http.MethodGet, "/ui/general", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, direct)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("direct: got %d, want 401", rec2.Code)
	}
	if rec2.Header().Get("WWW-Authenticate") == "" {
		t.Error("direct: missing WWW-Authenticate")
	}
}

// Repeated wrong credentials from one source are throttled rather than
// answered at line rate forever.
func TestAuthFailuresAreThrottled(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, "u", "p")}
	attempt := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.9:40000"
		req.SetBasicAuth("u", "wrong")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < authFailureLimit; i++ {
		if got := attempt().Code; got != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, got)
		}
	}
	rec := attempt()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: got %d, want 429", authFailureLimit, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}

	// A different source is unaffected — the limit is per-source, not global.
	other := httptest.NewRequest(http.MethodGet, "/", nil)
	other.RemoteAddr = "203.0.113.10:40000"
	other.SetBasicAuth("u", "p")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, other)
	if rec2.Code != http.StatusOK {
		t.Errorf("unrelated source got %d, want 200", rec2.Code)
	}
}

// A successful login clears the counter, so an operator who mistypes a few
// times and then gets it right is not left locked out.
func TestSuccessClearsAuthFailures(t *testing.T) {
	r := &Router{Proxy: okHandler("proxied"), Auth: staticAuth(true, "u", "p")}
	send := func(pass string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.11:40000"
		req.SetBasicAuth("u", pass)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < authFailureLimit-1; i++ {
		send("wrong")
	}
	if got := send("p"); got != http.StatusOK {
		t.Fatalf("correct password rejected: %d", got)
	}
	for i := 0; i < authFailureLimit-1; i++ {
		if got := send("wrong"); got != http.StatusUnauthorized {
			t.Fatalf("counter was not reset: got %d on attempt %d", got, i+1)
		}
	}
}

// The health path is configurable so reverse mode can stop shadowing a backend
// that serves the same route.
func TestHealthPathConfigurable(t *testing.T) {
	backend := okHandler("BACKEND-HEALTH")

	off := &Router{Proxy: backend, HealthPath: ""}
	rec := httptest.NewRecorder()
	off.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Body.String() != "BACKEND-HEALTH" {
		t.Errorf("disabled: got %q, want the backend's response", rec.Body.String())
	}

	moved := &Router{Proxy: backend, HealthPath: "/_proxy_health"}
	rec2 := httptest.NewRecorder()
	moved.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec2.Body.String() != "BACKEND-HEALTH" {
		t.Errorf("moved: /healthz should reach the backend, got %q", rec2.Body.String())
	}
	rec3 := httptest.NewRecorder()
	moved.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/_proxy_health", nil))
	if rec3.Code != http.StatusOK || rec3.Body.String() != "ok\n" {
		t.Errorf("moved: got %d %q", rec3.Code, rec3.Body.String())
	}
}

// Scrapers send no credentials, so enabling auth must not silently take
// monitoring down when the operator has opted into a public metrics endpoint.
func TestMetricsPublicBypassesAuth(t *testing.T) {
	gated := &Router{Proxy: okHandler("p"), Metrics: okHandler("# HELP"), Auth: staticAuth(true, "u", "p")}
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("default should stay gated, got %d", rec.Code)
	}

	public := &Router{Proxy: okHandler("p"), Metrics: okHandler("# HELP"),
		Auth: staticAuth(true, "u", "p"), MetricsPublic: true}
	rec2 := httptest.NewRecorder()
	public.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec2.Code != http.StatusOK {
		t.Errorf("metrics-public: got %d, want 200", rec2.Code)
	}

	// The exemption must not leak to anything else.
	rec3 := httptest.NewRecorder()
	public.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/ui/general", nil))
	if rec3.Code != http.StatusUnauthorized {
		t.Errorf("exemption leaked: got %d", rec3.Code)
	}
}

// Client access governs proxying. It must not lock an operator out of the
// admin surface — the controls that fix a bad rule are behind it.
func TestClientACLGatesProxyingNotAdmin(t *testing.T) {
	var asked []string
	r := &Router{
		Proxy: okHandler("PROXIED"),
		UI:    okHandler("ADMIN-UI"),
		ClientAllowed: func(ip string) (bool, string) {
			asked = append(asked, ip)
			return ip != "203.0.113.9", "deny 203.0.113.9"
		},
	}

	blocked := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	blocked.RemoteAddr = "203.0.113.9:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, blocked)
	if rec.Code != http.StatusForbidden {
		t.Errorf("denied client: got %d, want 403", rec.Code)
	}

	allowed := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	allowed.RemoteAddr = "10.0.0.5:5000"
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, allowed)
	if rec2.Body.String() != "PROXIED" {
		t.Errorf("permitted client: got %q", rec2.Body.String())
	}

	// The same denied address reaching the admin surface is an operator, not a
	// proxy client, and must still get through.
	admin := httptest.NewRequest(http.MethodGet, "/ui/general", nil)
	admin.RemoteAddr = "203.0.113.9:5000"
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, admin)
	if rec3.Body.String() != "ADMIN-UI" {
		t.Errorf("admin access from a denied client: got %q", rec3.Body.String())
	}

	// The check is asked about the address without its ephemeral port.
	for _, ip := range asked {
		if strings.Contains(ip, ":") {
			t.Errorf("ClientAllowed asked about %q, want a bare address", ip)
		}
	}
}

// CONNECT is proxying too, so the client gate applies to it.
func TestClientACLAppliesToConnect(t *testing.T) {
	r := &Router{
		Proxy:         okHandler("PROXIED"),
		ClientAllowed: func(string) (bool, string) { return false, "default deny" },
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	req.RemoteAddr = "203.0.113.9:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

// In reverse mode every request is origin-form, so a gate keyed on "is this
// request in proxy form" would leave a reverse proxy with no client access
// control at all. The gate belongs at the dispatch to the proxy handler.
func TestClientACLAppliesInReverseMode(t *testing.T) {
	r := &Router{
		Proxy:         okHandler("BACKEND"),
		UI:            okHandler("ADMIN-UI"),
		ClientAllowed: func(string) (bool, string) { return false, "default deny" },
	}
	// An ordinary origin-form request, exactly what a reverse proxy serves.
	req := httptest.NewRequest(http.MethodGet, "/some/backend/path", nil)
	req.RemoteAddr = "203.0.113.9:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403 for a denied client in reverse mode", rec.Code)
	}

	// The admin surface is still reachable from that address.
	admin := httptest.NewRequest(http.MethodGet, "/ui/general", nil)
	admin.RemoteAddr = "203.0.113.9:5000"
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, admin)
	if rec2.Body.String() != "ADMIN-UI" {
		t.Errorf("admin from a denied client: got %q", rec2.Body.String())
	}
}

func TestQuotaRefusalIs429WithRetryAfter(t *testing.T) {
	r := &Router{
		Proxy: okHandler("PROXIED"),
		Quota: func(string) (bool, time.Duration, string) {
			return false, 2500 * time.Millisecond, "client-requests"
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}
	// Retry-After is whole seconds and must round up: telling a client to retry
	// in 2s when 2.5s of the wait remains just produces a second refusal.
	if got := rec.Header().Get("Retry-After"); got != "3" {
		t.Errorf("Retry-After = %q, want %q", got, "3")
	}
	// The body names which allowance ran out; "429" alone is not actionable.
	if !strings.Contains(rec.Body.String(), "client-requests") {
		t.Errorf("body does not name the exhausted quota: %q", rec.Body.String())
	}
}

// Quotas govern proxying. Locking an operator out of the page that raises an
// exhausted quota would be a trap with no way out.
func TestQuotaDoesNotGateTheAdminSurface(t *testing.T) {
	var asked int
	r := &Router{
		Proxy:   okHandler("PROXIED"),
		UI:      okHandler("ADMIN-UI"),
		Metrics: okHandler("METRICS"),
		Quota: func(string) (bool, time.Duration, string) {
			asked++
			return false, time.Second, "global-requests"
		},
	}
	for _, path := range []string{"/ui/general", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.1.2.3:5000"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Errorf("%s was quota-gated", path)
		}
	}
	if asked != 0 {
		t.Errorf("quota consulted %d times for admin requests, want 0", asked)
	}
}

// An unauthenticated or barred client must not be able to spend a legitimate
// client's allowance, so the quota is charged last of the three gates.
func TestQuotaIsNotChargedForRejectedRequests(t *testing.T) {
	var charged int
	r := &Router{
		Proxy:         okHandler("PROXIED"),
		Auth:          func() (bool, string, string) { return true, "u", "p" },
		ClientAllowed: func(ip string) (bool, string) { return ip != "203.0.113.9", "deny" },
		Quota: func(string) (bool, time.Duration, string) {
			charged++
			return true, 0, ""
		},
	}

	// No credentials: refused before the quota is consulted.
	noAuth := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	noAuth.RemoteAddr = "10.1.2.3:5000"
	r.ServeHTTP(httptest.NewRecorder(), noAuth)

	// Correct credentials but a barred address: still refused before the quota.
	barred := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	barred.RemoteAddr = "203.0.113.9:5000"
	barred.SetBasicAuth("u", "p")
	r.ServeHTTP(httptest.NewRecorder(), barred)

	if charged != 0 {
		t.Errorf("quota charged %d times for refused requests, want 0", charged)
	}

	ok := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ok.RemoteAddr = "10.1.2.3:5000"
	ok.SetBasicAuth("u", "p")
	r.ServeHTTP(httptest.NewRecorder(), ok)
	if charged != 1 {
		t.Errorf("quota charged %d times for an admitted request, want 1", charged)
	}
}

// CONNECT is one request but arbitrary traffic, so it must be admitted through
// the same gate rather than slipping past it.
func TestQuotaAppliesToConnect(t *testing.T) {
	var asked int
	r := &Router{
		Proxy: okHandler("PROXIED"),
		Quota: func(string) (bool, time.Duration, string) {
			asked++
			return false, time.Second, "client-requests"
		},
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("CONNECT got %d, want 429", rec.Code)
	}
	if asked != 1 {
		t.Errorf("quota consulted %d times, want 1", asked)
	}
}

// The health endpoint is a liveness probe, not proxied traffic. Letting a quota
// refuse it would have an orchestrator restart the proxy precisely when it is
// busiest.
func TestQuotaDoesNotGateHealth(t *testing.T) {
	r := &Router{
		Proxy:      okHandler("PROXIED"),
		HealthPath: DefaultHealthPath,
		Quota: func(string) (bool, time.Duration, string) {
			return false, time.Second, "global-requests"
		},
	}
	req := httptest.NewRequest(http.MethodGet, DefaultHealthPath, nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("health probe got %d, want 200", rec.Code)
	}
}

// A browser fetches the PAC file before it has anywhere to send credentials, so
// the endpoint has to answer ahead of the auth gate. That is precisely why what
// goes in the file is an operator decision rather than a default.
func TestPACIsServedWithoutAuthentication(t *testing.T) {
	r := &Router{
		Proxy: okHandler("PROXIED"),
		Auth:  func() (bool, string, string) { return true, "u", "p" },
		PAC:   okHandler("function FindProxyForURL(){}"),
	}
	req := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want the PAC served without credentials", rec.Code)
	}
	if rec.Body.String() != "function FindProxyForURL(){}" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// Nil means the endpoint does not exist, which is what "off by default" has to
// mean for something served unauthenticated.
func TestPACAbsentWhenNotConfigured(t *testing.T) {
	r := &Router{Proxy: okHandler("PROXIED")}
	req := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Body.String() == "function FindProxyForURL(){}" {
		t.Error("the PAC endpoint answered while disabled")
	}
}

// A client asking the proxy to fetch http://host/proxy.pac wants that origin's
// file, not ours. Serving ours would make the path unproxyable.
func TestPACDoesNotShadowAProxiedRequest(t *testing.T) {
	r := &Router{
		Proxy: okHandler("PROXIED"),
		PAC:   okHandler("OURS"),
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/proxy.pac", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Body.String() != "PROXIED" {
		t.Errorf("body = %q, want the origin's file", rec.Body.String())
	}
}
