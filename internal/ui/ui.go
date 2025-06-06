package ui

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/pod32g/proxy/internal/config"
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
	mux.HandleFunc("/auth", h.authPage)
	mux.HandleFunc("/header", h.addHeader)
	mux.HandleFunc("/delete", h.deleteHeader)
	mux.HandleFunc("/loglevel", h.setLogLevel)
	mux.HandleFunc("/stats", h.setStats)
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
	ClientCount   int
	ClientAddrs   []string
	StatsEnabled  bool
	Stats         []server.Stat
}

var layout = template.Must(template.New("layout").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>Proxy Config</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
    body { font-family: Arial, sans-serif; }
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
<label>Name: <input name="name"></label>
<label>Value: <input name="value"></label>
<label>Client: <input name="client" placeholder="(global)"></label>
<button type="submit">Save</button>
</form>
<h2>Delete Header</h2>
<form method="POST" action="delete">
<label>Name: <input name="name"></label>
<label>Client: <input name="client" placeholder="(global)"></label>
<button type="submit">Delete</button>
</form>

<h2>Log Level</h2>
Current: {{.LogLevel}}
<form method="POST" action="loglevel">
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
<table>
<thead><tr><th>Host</th><th>Count</th></tr></thead>
{{range .Stats}}
<tr><td>{{.Host}}</td><td>{{.Count}}</td></tr>
{{end}}
</table>
{{end}}
<h2>Analysis</h2>
<form method="POST" action="stats">
    <label><input type="checkbox" name="enabled" {{if .StatsEnabled}}checked{{end}}> Enable Analysis</label>
    <button type="submit">Save</button>
</form>
{{end}}`))

var authPage = template.Must(template.Must(layout.Clone()).Parse(`{{define "content"}}
<h2>Authentication</h2>
<form method="POST" action="auth">
    <label><input type="checkbox" name="enabled" {{if .AuthEnabled}}checked{{end}}> Enable Auth</label><br>
    <label>User: <input name="username" value="{{.Username}}"></label><br>
    <label>Pass: <input type="password" name="password" placeholder="(unchanged)"></label><br>
    <button type="submit">Save</button>
</form>
{{end}}`))

func (h *handler) makeData() pageData {
	enabled, user, _ := h.cfg.GetAuth()
	data := pageData{
		Headers:       h.cfg.GetHeaders(),
		ClientHeaders: h.cfg.GetAllClientHeaders(),
		LogLevel:      config.LevelString(h.cfg.GetLogLevel()),
		AuthEnabled:   enabled,
		Username:      user,
		ClientCount:   0,
		ClientAddrs:   nil,
		StatsEnabled:  h.cfg.StatsEnabledState(),
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
	http.Redirect(w, r, "/general", http.StatusSeeOther)
}

func (h *handler) general(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	generalPage.Execute(w, h.makeData())
}

func (h *handler) analytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	analyticsPage.Execute(w, h.makeData())
}

func (h *handler) authPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	authPage.Execute(w, h.makeData())
}

func (h *handler) addHeader(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
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
			h.logger.Info("Set header", name, value)
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
	name := r.FormValue("name")
	client := r.FormValue("client")
	if name != "" {
		if client == "" {
			h.cfg.DeleteHeader(name)
		} else {
			h.cfg.DeleteClientHeader(client, name)
		}
		if h.logger != nil {
			h.logger.Info("Deleted header", name)
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
	levelStr := r.FormValue("level")
	level := config.ParseLogLevel(levelStr)
	h.cfg.SetLogLevel(level)
	if h.logger != nil {
		h.logger.SetLevel(level)
		h.logger.Info("Set log level", levelStr)
	}
	if h.store != nil {
		h.store.Save(h.cfg)
	}
	http.Redirect(w, r, "/ui/general", http.StatusSeeOther)
}

func (h *handler) setAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
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
		h.logger.Info("Updated auth settings", "enabled=", enabled, "user=", user)
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
