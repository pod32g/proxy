// Command webserver serves the standalone browser UI in web/.
//
// It is a thin static file server: the API it drives lives in the proxy, not
// here. Point it at a running proxy with -api; without that the page loads and
// every panel reports that it could not reach the API, which is what used to
// happen with no way to fix it.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
)

func newHandler(dir, apiBase string) http.Handler {
	mux := http.NewServeMux()
	// Injected rather than baked into script.js so the same static files work
	// against any proxy.
	mux.HandleFunc("/config.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "window.PROXY_API_BASE = %q;\n", apiBase)
	})
	mux.Handle("/", http.FileServer(http.Dir(dir)))
	return mux
}

func main() {
	addr := flag.String("http", ":9090", "listen address")
	dir := flag.String("static", "./web", "static content directory")
	apiBase := flag.String("api", "", "base URL of the proxy's API (e.g. http://localhost:8080); empty means same origin")
	flag.Parse()

	srv := &http.Server{
		Addr:    *addr,
		Handler: newHandler(*dir, *apiBase),
		// Same reasoning as the proxy's own listeners: bound the handshake and
		// idle time, not the transfer.
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	log.Println("serving", *dir, "on", *addr, "against API", *apiBase)
	log.Fatal(srv.ListenAndServe())
}
