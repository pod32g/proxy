package ui

import (
	"html/template"
	"net/http"

	"github.com/pod32g/proxy/internal/config"
	log "github.com/pod32g/simple-logger"
)

// New returns a handler that exposes a simple configuration UI.
func New(cfg *config.Config, store *config.Store, logger *log.Logger) http.Handler {
	h := &handler{cfg: cfg, store: store, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/header", h.addHeader)
	mux.HandleFunc("/delete", h.deleteHeader)
	mux.HandleFunc("/loglevel", h.setLogLevel)
	return mux
}

type handler struct {
	cfg    *config.Config
	store  *config.Store
	logger *log.Logger
}

type pageData struct {
	Headers  map[string]string
	LogLevel string
}

var page = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html><head><title>Proxy Config</title></head><body>
<h1>Headers</h1>
<table>
{{range $k, $v := .Headers}}
<tr><td>{{$k}}</td><td>{{$v}}</td></tr>
{{end}}
</table>
<h2>Add/Update Header</h2>
<form method="POST" action="header">
Name: <input name="name">
Value: <input name="value">
<button type="submit">Save</button>
</form>
<h2>Delete Header</h2>
<form method="POST" action="delete">
Name: <input name="name">
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
</body></html>`))

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	data := pageData{
		Headers:  h.cfg.GetHeaders(),
		LogLevel: config.LevelString(h.cfg.GetLogLevel()),
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
	if name != "" {
		h.cfg.SetHeader(name, value)
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
	if name != "" {
		h.cfg.DeleteHeader(name)
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
	}
	if h.store != nil {
		h.store.Save(h.cfg)
	}
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}
