package main

import (
	"flag"
	"net/url"
	"os"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/proxy"
	"github.com/pod32g/proxy/internal/server"
	log "github.com/pod32g/simple-logger"
)

func main() {
	cfg := config.Config{}
	flag.StringVar(&cfg.TargetURL, "target", "http://localhost:9000", "backend URL")
	flag.StringVar(&cfg.HTTPAddr, "http", ":8080", "HTTP listen address")
	flag.StringVar(&cfg.HTTPSAddr, "https", "", "HTTPS listen address")
	flag.StringVar(&cfg.CertFile, "cert", "", "TLS certificate file")
	flag.StringVar(&cfg.KeyFile, "key", "", "TLS key file")
	flag.Parse()

	logger := log.NewLogger(os.Stdout, log.INFO, &log.DefaultFormatter{})

	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		logger.Fatal("Invalid backend URL: %v", err)
	}

	handler := proxy.New(target, logger)

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
