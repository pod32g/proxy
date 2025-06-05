package ui

import (
	"html/template"
	"net/http"

	"github.com/pod32g/proxy/internal/config"
)

// New returns a handler that exposes a simple configuration UI.
func New(cfg *config.Config) http.Handler {
	h := &handler{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/header", h.addHeader)
	mux.HandleFunc("/delete", h.deleteHeader)
	return mux
}

type handler struct {
	cfg *config.Config
}

var page = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html><head><title>Proxy Config</title></head><body>
<h1>Headers</h1>
<table>
{{range $k, $v := .}}
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
</body></html>`))

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	page.Execute(w, h.cfg.GetHeaders())
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
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handler) deleteHeader(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	name := r.FormValue("name")
	if name != "" {
		h.cfg.DeleteHeader(name)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
