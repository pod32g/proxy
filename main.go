package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/proxy"
	"github.com/pod32g/proxy/internal/server"
	log "github.com/pod32g/simple-logger"
)

type headerFlags map[string]string

func (h *headerFlags) String() string {
	var parts []string
	for k, v := range *h {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func (h *headerFlags) Set(value string) error {
	if *h == nil {
		*h = make(map[string]string)
	}
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid header %q", value)
	}
	(*h)[parts[0]] = parts[1]
	return nil
}

func main() {
	cfg := config.Config{}
	flag.StringVar(&cfg.TargetURL, "target", "http://localhost:9000", "backend URL")
	flag.StringVar(&cfg.HTTPAddr, "http", ":8080", "HTTP listen address")
	flag.StringVar(&cfg.HTTPSAddr, "https", "", "HTTPS listen address")
	flag.StringVar(&cfg.CertFile, "cert", "", "TLS certificate file")
	flag.StringVar(&cfg.KeyFile, "key", "", "TLS key file")
	var headers headerFlags
	flag.Var(&headers, "header", "Custom header to add to upstream requests (format Name=Value, can be repeated)")
	flag.Parse()

	cfg.Headers = headers

	logger := log.NewLogger(os.Stdout, log.INFO, &log.DefaultFormatter{})

	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		logger.Fatal("Invalid backend URL: %v", err)
	}

	handler := proxy.New(target, logger, cfg.Headers)

	srv := server.Server{
		HTTPAddr:  cfg.HTTPAddr,
		HTTPSAddr: cfg.HTTPSAddr,
		CertFile:  cfg.CertFile,
		KeyFile:   cfg.KeyFile,
		Handler:   handler,
		Logger:    logger,
	}

	if err := srv.Start(); err != nil {
		logger.Fatal("Server failed: %v", err)
	}
}
