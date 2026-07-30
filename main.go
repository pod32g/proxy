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
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

// environment records which settings the operator supplied through the
// environment. Without that record an env var is indistinguishable from a
// built-in default, and the stored configuration would silently outrank it.
type environment struct{ set map[string]bool }

func newEnvironment() *environment { return &environment{set: map[string]bool{}} }

func (e *environment) get(key, def string) string {
	if v := os.Getenv(key); v != "" {
		e.set[key] = true
		return v
	}
	return def
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

// startupValues holds the settings the operator gave us on the command line or
// in the environment. Store.Load overwrites the live config with whatever the
// database holds, so these are re-applied afterwards to keep the precedence
// flag > env > stored > default.
type startupValues struct {
	logLevel     log.LogLevel
	authEnabled  bool
	username     string
	password     string
	proxyName    string
	proxyID      string
	statsEnabled bool
}

// overrides answers whether a setting was set explicitly, by either route.
type overrides struct {
	flags map[string]bool
	envs  map[string]bool
}

func (o overrides) has(flagName, envName string) bool {
	return o.flags[flagName] || o.envs[envName]
}

// reapply restores the explicitly-supplied settings over whatever Load read
// from the database.
func reapply(cfg *config.Config, cli startupValues, set overrides) {
	if set.has("log-level", "PROXY_LOG_LEVEL") {
		cfg.SetLogLevel(cli.logLevel)
	}
	if set.has("auth", "PROXY_AUTH_ENABLED") {
		cfg.SetAuthEnabled(cli.authEnabled)
	}
	if set.has("stats", "PROXY_STATS_ENABLED") {
		cfg.SetStatsEnabled(cli.statsEnabled)
	}
	if set.has("proxy-name", "PROXY_NAME") {
		cfg.SetProxyName(cli.proxyName)
	}
	if set.has("proxy-id", "PROXY_ID") {
		cfg.SetProxyID(cli.proxyID)
	}
	// Credentials move together, so read the current pair and replace only the
	// half that was given explicitly.
	userSet := set.has("auth-user", "PROXY_AUTH_USER")
	passSet := set.has("auth-pass", "PROXY_AUTH_PASS")
	if userSet || passSet {
		_, user, pass := cfg.GetAuth()
		if userSet {
			user = cli.username
		}
		if passSet {
			pass = cli.password
		}
		cfg.SetCredentials(user, pass)
	}
}

func main() {
	env := newEnvironment()
	cfg := &config.Config{}
	flag.StringVar(&cfg.Mode, "mode", env.get("PROXY_MODE", "forward"), "proxy mode: forward or reverse")
	flag.StringVar(&cfg.TargetURL, "target", env.get("PROXY_TARGET", "http://localhost:9000"), "backend URL")
	flag.StringVar(&cfg.HTTPAddr, "http", env.get("PROXY_HTTP_ADDR", ":8080"), "HTTP listen address")
	flag.StringVar(&cfg.HTTPSAddr, "https", env.get("PROXY_HTTPS_ADDR", ""), "HTTPS listen address")
	flag.StringVar(&cfg.CertFile, "cert", env.get("PROXY_CERT_FILE", ""), "TLS certificate file")
	flag.StringVar(&cfg.KeyFile, "key", env.get("PROXY_KEY_FILE", ""), "TLS key file")
	flag.BoolVar(&cfg.AuthEnabled, "auth", env.get("PROXY_AUTH_ENABLED", "") == "true", "enable basic auth")
	flag.StringVar(&cfg.Username, "auth-user", env.get("PROXY_AUTH_USER", ""), "username for basic auth")
	flag.StringVar(&cfg.Password, "auth-pass", env.get("PROXY_AUTH_PASS", ""), "password for basic auth")
	flag.StringVar(&cfg.SecretKey, "secret", env.get("PROXY_SECRET_KEY", ""), "secret key for encryption")
	flag.StringVar(&cfg.ProxyName, "proxy-name", env.get("PROXY_NAME", ""), "proxy name for identification")
	flag.StringVar(&cfg.ProxyID, "proxy-id", env.get("PROXY_ID", ""), "proxy identifier")
	flag.BoolVar(&cfg.StatsEnabled, "stats", env.get("PROXY_STATS_ENABLED", "") == "true", "enable traffic analysis")
	logLevelStr := env.get("PROXY_LOG_LEVEL", "INFO")
	flag.StringVar(&logLevelStr, "log-level", logLevelStr, "Log level ("+strings.Join(config.LogLevels, ", ")+")")
	var headers headerFlags
	flag.Var(&headers, "header", "Custom header to add to upstream requests (format Name=Value, can be repeated)")
	dbPath := flag.String("db", env.get("PROXY_DB_PATH", "config.db"), "sqlite database path")
	flag.Parse()

	// Reject unusable settings here rather than starting up in a mode the
	// operator did not ask for. A mistyped -mode used to fall through to
	// "reverse" and quietly proxy to the default backend.
	if cfg.Mode != "forward" && cfg.Mode != "reverse" {
		fatalf("invalid -mode %q (want \"forward\" or \"reverse\")", cfg.Mode)
	}
	logLevel, err := config.ParseLogLevelStrict(logLevelStr)
	if err != nil {
		fatalf("invalid -log-level: %v", err)
	}
	var target *url.URL
	if cfg.Mode == "reverse" {
		target, err = url.Parse(cfg.TargetURL)
		if err != nil {
			fatalf("invalid -target %q: %v", cfg.TargetURL, err)
		}
	}

	cfg.Headers = headers
	cfg.LogLevel = logLevel

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	cli := startupValues{
		logLevel:     logLevel,
		authEnabled:  cfg.AuthEnabled,
		username:     cfg.Username,
		password:     cfg.Password,
		proxyName:    cfg.ProxyName,
		proxyID:      cfg.ProxyID,
		statsEnabled: cfg.StatsEnabled,
	}
	set := overrides{flags: setFlags, envs: env.set}

	store, err := config.NewStore(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open DB: %v\n", err)
	} else {
		defer store.Close()
		if err := store.Load(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		}
		reapply(cfg, cli, set)
	}

	logger := log.NewLogger(os.Stdout, cfg.GetLogLevel(), &log.DefaultFormatter{})

	if config.CredentialsAtRisk(cfg) {
		logger.Warn("Credentials will be stored unencrypted in", *dbPath,
			"- set -secret (or PROXY_SECRET_KEY) to encrypt them at rest")
	}
	if store != nil {
		// Also rewrites credentials sealed by older builds under the current
		// key derivation.
		if err := store.Save(cfg); err != nil {
			logger.Error("Failed to persist config: %v", err)
		}
	}

	metrics := server.NewMetrics()
	tracker := server.NewClientTracker()
	tracker.SetGauge(metrics.Clients)
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
		h := proxy.New(target, logger, cfg.GetHeadersForClient)
		handler = server.StatsMiddleware(h, stats, cfg.StatsEnabledState, func(r *http.Request) string { return target.Host })
	}
	handler = server.MetricsMiddleware(handler, metrics)
	uiHandler := ui.New(cfg, store, logger, tracker, stats)
	apiHandler := api.New(cfg, store, logger, stats)
	mux := &server.Router{
		Proxy:   handler,
		UI:      uiHandler,
		API:     apiHandler,
		Metrics: promhttp.Handler(),
		// Consulted per request, so credentials changed through the UI or API
		// take effect without a restart.
		Auth:   cfg.GetAuth,
		Logger: logger,
	}

	srv := server.Server{
		HTTPAddr:  cfg.HTTPAddr,
		HTTPSAddr: cfg.HTTPSAddr,
		CertFile:  cfg.CertFile,
		KeyFile:   cfg.KeyFile,
		Handler:   mux,
		Logger:    logger,
		Clients:   tracker,
	}

	if err := srv.Start(); err != nil {
		logger.Fatal("Server failed: %v", err)
	}
}
