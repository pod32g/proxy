package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/server"
	log "github.com/pod32g/simple-logger"
)

// New returns a handler that exposes a simple configuration UI.
func New(cfg *config.Config, store *config.Store, logger *log.Logger, clients *server.ClientTracker, stats *server.DomainStats) http.Handler {
	h := &handler{cfg: cfg, store: store, logger: logger, clients: clients, stats: stats}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/general", h.general)
	mux.HandleFunc("/analytics", h.analytics)
	mux.HandleFunc("/identity", h.identityPage)
	mux.HandleFunc("/set-identity", h.setIdentity)
	mux.HandleFunc("/policy", h.policyPage)
	mux.HandleFunc("/set-policy", h.setPolicy)
	mux.HandleFunc("/test-policy", h.testPolicy)
	mux.HandleFunc("/auth", h.authPage)
	mux.HandleFunc("/set-auth", h.setAuth)
	mux.HandleFunc("/header", h.addHeader)
	mux.HandleFunc("/delete", h.deleteHeader)
	mux.HandleFunc("/loglevel", h.setLogLevel)
	mux.HandleFunc("/stats", h.setStats)
	mux.HandleFunc("/stats-events", h.statsEvents)
	mux.HandleFunc("/events", h.events)
	return mux
}

type handler struct {
	cfg     *config.Config
	store   *config.Store
	logger  *log.Logger
	clients *server.ClientTracker
	stats   *server.DomainStats
}

type pageData struct {
	Headers       map[string]string
	ClientHeaders map[string]map[string]string
	LogLevel      string
	AuthEnabled   bool
	Username      string
	ProxyName     string
	ProxyID       string
	ClientCount   int
	ClientAddrs   []string
	StatsEnabled  bool
	Stats         []server.Stat
	CSRFToken     string

	DestinationRules string
	ClientRules      string
	PolicyError      string
	TestResult       string
}

// CSRF uses the double-submit pattern: a random token is stored in a cookie and
// echoed in a hidden form field, and a request is honoured only when the two
// match. Another origin can cause the browser to send the cookie but cannot
// read it to populate the field. This matters because basic-auth credentials
// are attached to cross-site requests automatically, so an authenticated
// operator visiting a hostile page could otherwise have the proxy reconfigured
// underneath them.
const csrfCookieName = "proxy_csrf"
const csrfFieldName = "csrf_token"

func newCSRFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// issueCSRF returns the caller's token, minting and setting one if needed.
func (h *handler) issueCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	token, err := newCSRFToken()
	if err != nil {
		if h.logger != nil {
			h.logger.Errorf("Failed to generate CSRF token: %v", err)
		}
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:  csrfCookieName,
		Value: token,
		// The UI is mounted under /ui by the router; scope the cookie to match.
		Path:     "/ui",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	return token
}

// checkCSRF reports whether a state-changing request carries a form token
// matching its cookie, and writes the rejection when it does not.
func (h *handler) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "Missing CSRF cookie", http.StatusForbidden)
		return false
	}
	sent := r.FormValue(csrfFieldName)
	if sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(cookie.Value)) != 1 {
		if h.logger != nil {
			h.logger.Warn("Rejected request with bad CSRF token", log.String("path", r.URL.Path))
		}
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

var layout = template.Must(template.New("layout").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>Proxy Config</title>
    <!-- Styles are inline on purpose. A CDN <link> here would put a third
         party in the page where credentials are set, and would leave the admin
         UI unstyled and hanging on a blocked request in the restricted
         networks a proxy tends to be deployed into. -->
    <style>
    body { font-family: Arial, sans-serif; margin: 0; color: #212529; }
    h1, h2, h3, h5 { margin: 0.6em 0 0.4em; }
    .nav { list-style: none; padding: 0; margin: 0; }
    .nav-item { margin: 0; }
    .nav-link { display: block; padding: 8px 16px; color: #0d6efd; text-decoration: none; }
    .nav-link:hover { background: #e9ecef; }
    .text-center { text-align: center; }
    button, input, select { font: inherit; padding: 3px 6px; }
    button { cursor: pointer; }
    .sidebar {
        width: 220px;
        position: fixed;
        top: 0;
        left: 0;
        height: 100%;
        padding-top: 60px;
        background-color: #f8f9fa;
    }
    .content {
        margin-left: 240px;
        padding: 20px;
    }
    table { border-collapse: collapse; margin-bottom: 1em; }
    th, td { padding: 4px 8px; border: 1px solid #ccc; }
    form { margin-bottom: 1em; }
    </style>
</head>
<body>
<div class="sidebar">
    <h5 class="text-center">Menu</h5>
    <ul class="nav flex-column">
        <li class="nav-item"><a href="/ui/general" class="nav-link">General Settings</a></li>
        <li class="nav-item"><a href="/ui/analytics" class="nav-link">Analytics</a></li>
        <li class="nav-item"><a href="/ui/policy" class="nav-link">Policy</a></li>
        <li class="nav-item"><a href="/ui/identity" class="nav-link">Identity</a></li>
        <li class="nav-item"><a href="/ui/auth" class="nav-link">Authentication</a></li>
    </ul>
</div>
<div class="content">
<p>Connected clients: <span id="clients">{{.ClientCount}}</span></p>
<ul>
{{range .ClientAddrs}}
<li>{{.}}</li>
{{end}}
</ul>
{{template "content" .}}
</div>
<script>
var es = new EventSource('events');
es.onmessage = function(e){
    document.getElementById('clients').textContent = e.data;
};
</script>
</body>
</html>`))

var generalPage = template.Must(template.Must(layout.Clone()).Parse(`{{define "content"}}
<h1>Headers</h1>
<table>
<thead><tr><th>Name</th><th>Value</th></tr></thead>
{{range $k, $v := .Headers}}
<tr><td>{{$k}}</td><td>{{$v}}</td></tr>
{{end}}
</table>
<h2>Client Headers</h2>
{{range $c, $m := .ClientHeaders}}
<h3>{{$c}}</h3>
<table>
<thead><tr><th>Name</th><th>Value</th></tr></thead>
{{range $k, $v := $m}}
<tr><td>{{$k}}</td><td>{{$v}}</td></tr>
{{end}}
</table>
{{end}}
<h2>Add/Update Header</h2>
<form method="POST" action="header">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label>Name: <input name="name"></label>
<label>Value: <input name="value"></label>
<label>Client: <input name="client" placeholder="(global)"></label>
<button type="submit">Save</button>
</form>
<h2>Delete Header</h2>
<form method="POST" action="delete">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label>Name: <input name="name"></label>
<label>Client: <input name="client" placeholder="(global)"></label>
<button type="submit">Delete</button>
</form>

<h2>Log Level</h2>
Current: {{.LogLevel}}
<form method="POST" action="loglevel">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<select name="level">
<option>DEBUG</option>
<option>INFO</option>
<option>WARN</option>
<option>ERROR</option>
<option>FATAL</option>
</select>
<button type="submit">Set</button>
</form>
{{end}}`))

var analyticsPage = template.Must(template.Must(layout.Clone()).Parse(`{{define "content"}}
<h2>Top Websites</h2>
{{if .StatsEnabled}}
<table id="top">
<thead><tr><th>Host</th><th>Count</th></tr></thead>
<tbody>
{{range .Stats}}
<tr><td>{{.Host}}</td><td>{{.Count}}</td></tr>
{{end}}
</tbody>
</table>
<script>
var statsSrc = new EventSource('stats-events');
statsSrc.onmessage = function(e){
    var data = JSON.parse(e.data) || [];
    var body = document.querySelector('#top tbody');
    // Built as text nodes rather than an innerHTML string: hostnames come from
    // whatever clients ask the proxy for, and the initial server render escapes
    // them via html/template. Assembling markup here would have quietly undone
    // that on the first live update.
    body.replaceChildren();
    data.forEach(function(s){
        var tr = document.createElement('tr');
        var host = document.createElement('td');
        host.textContent = s.Host;
        var count = document.createElement('td');
        count.textContent = s.Count;
        tr.appendChild(host); tr.appendChild(count);
        body.appendChild(tr);
    });
};
</script>
{{end}}
<h2>Analysis</h2>
<form method="POST" action="stats">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label><input type="checkbox" name="enabled" {{if .StatsEnabled}}checked{{end}}> Enable Analysis</label>
    <button type="submit">Save</button>
</form>
{{end}}`))

var policyPage = template.Must(template.Must(layout.Clone()).Parse(`{{define "content"}}
<h2>Destination rules</h2>
<p>Ordered, first match wins. One rule per line; <code>#</code> comments allowed.<br>
<code>allow domain example.com</code> &middot; <code>deny cidr 10.0.0.0/8</code> &middot; <code>deny all</code></p>

<h2>Client rules</h2>
<p>Longest prefix wins. <code>allow 10.0.0.0/8</code> &middot; <code>deny 10.1.2.3</code> &middot;
<code>default deny</code><br>A client may carry its own destination rules:
<code>allow 10.0.0.0/8 { allow domain example.com; deny all }</code></p>

{{if .PolicyError}}<p><strong>Not applied:</strong> {{.PolicyError}}</p>{{end}}

<form method="POST" action="set-policy">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label>Destinations:<br><textarea name="destinations" rows="8" cols="60">{{.DestinationRules}}</textarea></label><br>
    <label>Clients:<br><textarea name="clients" rows="6" cols="60">{{.ClientRules}}</textarea></label><br>
    <button type="submit">Save</button>
</form>

<h2>Test a destination</h2>
<p>Answers which rule decides, without changing anything. Supply an address to
exercise <code>cidr</code> rules and the private-address default.</p>
<form method="POST" action="test-policy">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label>Host: <input name="host" placeholder="api.example.com"></label>
    <label>Address: <input name="ip" placeholder="203.0.113.5 (optional)"></label>
    <label>Client: <input name="client" placeholder="10.1.2.3 (optional)"></label>
    <button type="submit">Test</button>
</form>
{{if .TestResult}}<p><strong>Result:</strong> {{.TestResult}}</p>{{end}}
{{end}}`))

var identityPage = template.Must(template.Must(layout.Clone()).Parse(`{{define "content"}}
<h2>Proxy Identity</h2>
<form method="POST" action="set-identity">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label>Name: <input name="name" value="{{.ProxyName}}"></label><br>
    <label>ID: <input name="id" value="{{.ProxyID}}"></label><br>
    <button type="submit">Save</button>
</form>
{{end}}`))

var authPage = template.Must(template.Must(layout.Clone()).Parse(`{{define "content"}}
<h2>Authentication</h2>
<form method="POST" action="set-auth">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label><input type="checkbox" name="enabled" {{if .AuthEnabled}}checked{{end}}> Enable Auth</label><br>
    <label>User: <input name="username" value="{{.Username}}"></label><br>
    <label>Pass: <input type="password" name="password" placeholder="(unchanged)"></label><br>
    <button type="submit">Save</button>
</form>
{{end}}`))

func (h *handler) makeData(w http.ResponseWriter, r *http.Request) pageData {
	enabled, user, _ := h.cfg.GetAuth()
	// Read identity through the accessor: SetIdentity writes these under the
	// config lock, so touching the fields directly races with any concurrent save.
	proxyName, proxyID := h.cfg.GetIdentity()
	data := pageData{
		Headers:          h.cfg.GetHeaders(),
		ClientHeaders:    h.cfg.GetAllClientHeaders(),
		LogLevel:         config.LevelString(h.cfg.GetLogLevel()),
		AuthEnabled:      enabled,
		Username:         user,
		ProxyName:        proxyName,
		ProxyID:          proxyID,
		ClientCount:      0,
		ClientAddrs:      nil,
		StatsEnabled:     h.cfg.StatsEnabledState(),
		CSRFToken:        h.issueCSRF(w, r),
		DestinationRules: h.cfg.PolicyRulesText(),
		ClientRules:      h.cfg.ClientRulesText(),
	}
	if h.clients != nil {
		data.ClientCount = h.clients.Count()
		data.ClientAddrs = h.clients.Addrs()
	}
	if h.stats != nil && data.StatsEnabled {
		data.Stats = h.stats.Top(10)
	}
	return data
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui/general", http.StatusSeeOther)
}

func (h *handler) general(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	generalPage.Execute(w, h.makeData(w, r))
}

func (h *handler) analytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	analyticsPage.Execute(w, h.makeData(w, r))
}

func (h *handler) identityPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	identityPage.Execute(w, h.makeData(w, r))
}

func (h *handler) authPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	authPage.Execute(w, h.makeData(w, r))
}

func (h *handler) policyPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	policyPage.Execute(w, h.makeData(w, r))
}

func (h *handler) setPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	destinations := r.FormValue("destinations")
	clients := r.FormValue("clients")

	// Validate both before applying either, and re-render with the error rather
	// than redirecting: losing what the operator typed because line 7 was wrong
	// is how people stop using a form.
	data := h.makeData(w, r)
	data.DestinationRules, data.ClientRules = destinations, clients
	if _, err := policy.Parse(destinations); err != nil {
		data.PolicyError = "destinations: " + err.Error()
		policyPage.Execute(w, data)
		return
	}
	if _, err := policy.ParseClients(clients); err != nil {
		data.PolicyError = "clients: " + err.Error()
		policyPage.Execute(w, data)
		return
	}
	_ = h.cfg.SetPolicyRules(destinations)
	_ = h.cfg.SetClientRules(clients)
	if h.logger != nil {
		h.logger.Info("Updated policy")
	}
	if h.store != nil {
		h.store.Save(h.cfg)
	}
	http.Redirect(w, r, "/ui/policy", http.StatusSeeOther)
}

func (h *handler) testPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	data := h.makeData(w, r)
	host := r.FormValue("host")
	if host == "" {
		data.TestResult = "enter a host to test"
	} else {
		result := h.cfg.EvaluatePolicy(r.FormValue("client"), host, r.FormValue("ip"))
		verdict := "DENIED"
		if result.Allowed && result.ClientAllow {
			verdict = "ALLOWED"
		}
		data.TestResult = verdict + " — " + result.Reason
	}
	policyPage.Execute(w, data)
}

func (h *handler) addHeader(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	name := r.FormValue("name")
	value := r.FormValue("value")
	client := r.FormValue("client")
	if name != "" {
		if client == "" {
			h.cfg.SetHeader(name, value)
		} else {
			h.cfg.SetClientHeader(client, name, value)
		}
		if h.logger != nil {
			h.logger.Info("Set header", log.String("name", name),
				log.String("value", config.RedactHeaderValue(name, value)))
		}
		if h.store != nil {
			h.store.Save(h.cfg)
		}
	}
	http.Redirect(w, r, "/ui/general", http.StatusSeeOther)
}

func (h *handler) deleteHeader(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	name := r.FormValue("name")
	client := r.FormValue("client")
	if name != "" {
		if client == "" {
			h.cfg.DeleteHeader(name)
		} else {
			h.cfg.DeleteClientHeader(client, name)
		}
		if h.logger != nil {
			h.logger.Info("Deleted header", log.String("name", name))
		}
		if h.store != nil {
			h.store.Save(h.cfg)
		}
	}
	http.Redirect(w, r, "/ui/general", http.StatusSeeOther)
}

func (h *handler) setLogLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	levelStr := r.FormValue("level")
	level, err := config.ParseLogLevelStrict(levelStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.cfg.SetLogLevel(level)
	if h.logger != nil {
		h.logger.SetLevel(level)
		h.logger.Info("Set log level", log.String("level", levelStr))
	}
	if h.store != nil {
		h.store.Save(h.cfg)
	}
	http.Redirect(w, r, "/ui/general", http.StatusSeeOther)
}

func (h *handler) setIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	name := r.FormValue("name")
	id := r.FormValue("id")
	h.cfg.SetIdentity(name, id)
	if h.logger != nil {
		h.logger.Info("Updated identity", log.String("name", name), log.String("id", id))
	}
	if h.store != nil {
		h.store.Save(h.cfg)
	}
	http.Redirect(w, r, "/ui/identity", http.StatusSeeOther)
}

func (h *handler) setAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	enabled := r.FormValue("enabled") == "on"
	user := r.FormValue("username")
	pass := r.FormValue("password")
	_, curUser, curPass := h.cfg.GetAuth()
	if user == "" {
		user = curUser
	}
	if pass == "" {
		pass = curPass
	}
	h.cfg.SetAuth(enabled, user, pass)
	if h.logger != nil {
		h.logger.Info("Updated auth settings", log.Bool("enabled", enabled), log.String("user", user))
	}
	if h.store != nil {
		h.store.Save(h.cfg)
	}
	http.Redirect(w, r, "/ui/auth", http.StatusSeeOther)
}

func (h *handler) setStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	enabled := r.FormValue("enabled") == "on"
	h.cfg.SetStatsEnabled(enabled)
	if h.store != nil {
		h.store.Save(h.cfg)
	}
	http.Redirect(w, r, "/ui/analytics", http.StatusSeeOther)
}

func (h *handler) events(w http.ResponseWriter, r *http.Request) {
	if h.clients == nil {
		http.Error(w, "tracker not available", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := h.clients.Subscribe()
	defer h.clients.Unsubscribe(ch)
	notify := func(c int) {
		fmt.Fprintf(w, "data: %d\n\n", c)
		flusher.Flush()
	}
	for {
		select {
		case c, ok := <-ch:
			if !ok {
				return
			}
			notify(c)
		case <-r.Context().Done():
			return
		}
	}
}

func (h *handler) statsEvents(w http.ResponseWriter, r *http.Request) {
	if h.stats == nil {
		http.Error(w, "stats not available", http.StatusServiceUnavailable)
		return
	}
	if !h.cfg.StatsEnabledState() {
		http.Error(w, "analysis disabled", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := h.stats.Subscribe()
	defer h.stats.Unsubscribe(ch)
	for {
		select {
		case stats, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(stats)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
