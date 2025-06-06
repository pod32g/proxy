package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("http", ":9090", "listen address")
	dir := flag.String("static", "./web", "static content directory")
	flag.Parse()

	fs := http.FileServer(http.Dir(*dir))
	http.Handle("/", fs)
	log.Println("serving", *dir, "on", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
