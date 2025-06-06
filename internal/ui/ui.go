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
func New(cfg *config.Config, store *config.Store, logger *log.Logger, clients *server.ClientTracker) http.Handler {
	h := &handler{cfg: cfg, store: store, logger: logger, clients: clients}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/header", h.addHeader)
	mux.HandleFunc("/delete", h.deleteHeader)
	mux.HandleFunc("/loglevel", h.setLogLevel)
	mux.HandleFunc("/auth", h.setAuth)
	mux.HandleFunc("/events", h.events)
	return mux
}

type handler struct {
	cfg     *config.Config
	store   *config.Store
	logger  *log.Logger
	clients *server.ClientTracker
}

type pageData struct {
	Headers       map[string]string
	ClientHeaders map[string]map[string]string
	LogLevel      string
	AuthEnabled   bool
	Username      string
	ClientCount   int
	ClientAddrs   []string
}

var page = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>Proxy Config</title>
    <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    table { border-collapse: collapse; margin-bottom: 1em; }
    th, td { padding: 4px 8px; border: 1px solid #ccc; }
    form { margin-bottom: 1em; }
    </style>
</head>
<body>
<p>Connected clients: <span id="clients">{{.ClientCount}}</span></p>
<ul>
{{range .ClientAddrs}}
<li>{{.}}</li>
{{end}}
</ul>
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

<h2>Authentication</h2>
<form method="POST" action="auth">
    <label><input type="checkbox" name="enabled" {{if .AuthEnabled}}checked{{end}}> Enable Auth</label><br>
    <label>User: <input name="username" value="{{.Username}}"></label><br>
    <label>Pass: <input type="password" name="password" placeholder="(unchanged)"></label><br>
    <button type="submit">Save</button>
</form>
<script>
var es = new EventSource('events');
es.onmessage = function(e){
    document.getElementById('clients').textContent = e.data;
};
</script>
</body>
</html>`))

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	enabled, user, _ := h.cfg.GetAuth()
	data := pageData{
		Headers:       h.cfg.GetHeaders(),
		ClientHeaders: h.cfg.GetAllClientHeaders(),
		LogLevel:      config.LevelString(h.cfg.GetLogLevel()),
		AuthEnabled:   enabled,
		Username:      user,
		ClientCount:   0,
		ClientAddrs:   nil,
	}
	if h.clients != nil {
		data.ClientCount = h.clients.Count()
		data.ClientAddrs = h.clients.Addrs()
	}
	page.Execute(w, data)
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
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
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
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
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
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
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
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
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
