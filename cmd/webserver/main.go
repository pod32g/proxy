package main

import (
	"flag"
	"log"
	"net/http"
)

func newHandler(dir string) http.Handler {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir(dir))
	mux.Handle("/", fs)
	return mux
}

func main() {
	addr := flag.String("http", ":9090", "listen address")
	dir := flag.String("static", "./web", "static content directory")
	flag.Parse()

	handler := newHandler(*dir)
	log.Println("serving", *dir, "on", *addr)
	log.Fatal(http.ListenAndServe(*addr, handler))
}
