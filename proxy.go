package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	log "github.com/pod32g/simple-logger"
)

func main() {
	logger := log.NewLogger(os.Stdout, log.INFO, &log.DefaultFormatter{})
	// 1. Parse the target backend URL
	target, err := url.Parse("http://localhost:9000")
	if err != nil {
		logger.Fatal("Invalid backend URL: %v", err)
	}

	// 2. Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// 3. Customize Director (optional)—e.g., rewrite Host header
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Example: force a specific header for all upstream requests
		req.Header.Set("X-Forwarded-By", "MyGoProxy")
	}

	// 4. (Optional) Modify error handling
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		logger.Error("Upstream Error: %v", err)
		http.Error(rw, "Bad gateway", http.StatusBadGateway)
	}

	// 5. Set up the HTTP server with timeouts
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      proxy,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	logger.Info("Starting proxy on :8080 →", target)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatal("Server failed: %v", err)
	}
}
