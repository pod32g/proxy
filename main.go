package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/pod32g/proxy/internal/api"
	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/proxy"
	"github.com/pod32g/proxy/internal/server"
	"github.com/pod32g/proxy/internal/ui"
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

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := &config.Config{}
	flag.StringVar(&cfg.Mode, "mode", getenv("PROXY_MODE", "forward"), "proxy mode: forward or reverse")
	flag.StringVar(&cfg.TargetURL, "target", getenv("PROXY_TARGET", "http://localhost:9000"), "backend URL")
	flag.StringVar(&cfg.HTTPAddr, "http", getenv("PROXY_HTTP_ADDR", ":8080"), "HTTP listen address")
	flag.StringVar(&cfg.HTTPSAddr, "https", getenv("PROXY_HTTPS_ADDR", ""), "HTTPS listen address")
	flag.StringVar(&cfg.CertFile, "cert", getenv("PROXY_CERT_FILE", ""), "TLS certificate file")
	flag.StringVar(&cfg.KeyFile, "key", getenv("PROXY_KEY_FILE", ""), "TLS key file")
	flag.BoolVar(&cfg.AuthEnabled, "auth", getenv("PROXY_AUTH_ENABLED", "") == "true", "enable basic auth")
	flag.StringVar(&cfg.Username, "auth-user", getenv("PROXY_AUTH_USER", ""), "username for basic auth")
	flag.StringVar(&cfg.Password, "auth-pass", getenv("PROXY_AUTH_PASS", ""), "password for basic auth")
	flag.StringVar(&cfg.SecretKey, "secret", getenv("PROXY_SECRET_KEY", ""), "secret key for encryption")
	flag.BoolVar(&cfg.StatsEnabled, "stats", getenv("PROXY_STATS_ENABLED", "") == "true", "enable traffic analysis")
	logLevelStr := getenv("PROXY_LOG_LEVEL", "INFO")
	flag.StringVar(&logLevelStr, "log-level", logLevelStr, "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	var headers headerFlags
	flag.Var(&headers, "header", "Custom header to add to upstream requests (format Name=Value, can be repeated)")
	dbPath := flag.String("db", getenv("PROXY_DB_PATH", "config.db"), "sqlite database path")
	flag.Parse()

	cfg.Headers = headers
	cfg.LogLevel = config.ParseLogLevel(logLevelStr)

	store, err := config.NewStore(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open DB: %v\n", err)
	} else {
		if err := store.Load(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		}
		store.Save(cfg)
		defer store.Close()
	}

	logger := log.NewLogger(os.Stdout, cfg.LogLevel, &log.DefaultFormatter{})

	tracker := server.NewClientTracker()
	stats := server.NewDomainStats()

	var handler http.Handler
	if cfg.Mode == "forward" {
		h := proxy.NewForward(logger, cfg.GetHeadersForClient)
		handler = server.StatsMiddleware(h, stats, cfg.StatsEnabledState, func(r *http.Request) string {
			if r.Method == http.MethodConnect {
				return r.Host
			}
			return r.URL.Host
		})
	} else {
		target, err := url.Parse(cfg.TargetURL)
		if err != nil {
			logger.Fatal("Invalid backend URL: %v", err)
		}
		h := proxy.New(target, logger, cfg.GetHeadersForClient)
		handler = server.StatsMiddleware(h, stats, cfg.StatsEnabledState, func(r *http.Request) string { return target.Host })
	}
	uiHandler := ui.New(cfg, store, logger, tracker, stats)
	apiHandler := api.New(cfg, store, logger, stats)
	mux := &server.Router{Proxy: handler, UI: uiHandler, API: apiHandler, Metrics: server.MetricsHandler(), AuthEnabled: cfg.AuthEnabled, Username: cfg.Username, Password: cfg.Password}
	wrapped := server.MetricsMiddleware(mux)

	srv := server.Server{
		HTTPAddr:  cfg.HTTPAddr,
		HTTPSAddr: cfg.HTTPSAddr,
		CertFile:  cfg.CertFile,
		KeyFile:   cfg.KeyFile,
		Handler:   wrapped,
		Logger:    logger,
		Clients:   tracker,
	}

	if err := srv.Start(); err != nil {
		logger.Fatal("Server failed: %v", err)
	}
}
