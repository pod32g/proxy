package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pod32g/proxy/internal/api"
	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/proxy"
	"github.com/pod32g/proxy/internal/server"
	"github.com/pod32g/proxy/internal/ui"
	log "github.com/pod32g/simple-logger"
	"github.com/prometheus/client_golang/prometheus"
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
	allowPrivate := flag.Bool("allow-private", env.get("PROXY_ALLOW_PRIVATE", "") == "true",
		"allow proxying to loopback, private and link-local addresses (off by default: a forward proxy takes destinations from untrusted clients)")
	var policyRules policyFlags
	flag.Var(&policyRules, "policy-rule",
		"destination rule, first match wins (e.g. \"allow domain *.example.com\", \"deny cidr 10.0.0.0/8\", \"deny all\"); repeatable")
	policyFile := flag.String("policy-file", env.get("PROXY_POLICY_FILE", ""),
		"file of destination rules, one per line; # comments allowed")
	connectPorts := flag.String("connect-ports", env.get("PROXY_CONNECT_PORTS", "443"),
		"comma-separated ports CONNECT may tunnel to")
	healthPath := flag.String("health-path", env.get("PROXY_HEALTH_PATH", server.DefaultHealthPath),
		"path answered without authentication for liveness probes; empty disables it (in reverse mode it shadows the backend)")
	adminAddr := flag.String("admin-http", env.get("PROXY_ADMIN_ADDR", ""),
		"serve the UI, API and metrics on their own listener; when set they are not served on the proxy port")
	adminCert := flag.String("admin-cert", env.get("PROXY_ADMIN_CERT_FILE", ""), "TLS certificate for the admin listener")
	adminKey := flag.String("admin-key", env.get("PROXY_ADMIN_KEY_FILE", ""), "TLS key for the admin listener")
	metricsPublic := flag.Bool("metrics-public", env.get("PROXY_METRICS_PUBLIC", "") == "true",
		"serve /metrics without authentication so scrapers that send no credentials keep working")
	authPassFile := flag.String("auth-pass-file", env.get("PROXY_AUTH_PASS_FILE", ""),
		"file containing the basic-auth password; preferred over -auth-pass, which is visible in ps")
	secretFile := flag.String("secret-file", env.get("PROXY_SECRET_FILE", ""),
		"file containing the credential-encryption secret; preferred over -secret, which is visible in ps")
	healthcheck := flag.Bool("healthcheck", false,
		"probe the local health endpoint and exit 0 or 1 (used by the container HEALTHCHECK)")
	logFormatStr := env.get("PROXY_LOG_FORMAT", "text")
	flag.StringVar(&logFormatStr, "log-format", logFormatStr,
		"Log output format ("+strings.Join(config.LogFormats, ", ")+")")
	logLevelStr := env.get("PROXY_LOG_LEVEL", "INFO")
	flag.StringVar(&logLevelStr, "log-level", logLevelStr, "Log level ("+strings.Join(config.LogLevels, ", ")+")")
	var headers headerFlags
	flag.Var(&headers, "header", "Custom header to add to upstream requests (format Name=Value, can be repeated)")
	dbPath := flag.String("db", env.get("PROXY_DB_PATH", "config.db"), "sqlite database path")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck(cfg.HTTPAddr, *healthPath))
	}

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
	logFormat, err := config.ParseLogFormat(logFormatStr)
	if err != nil {
		fatalf("invalid -log-format: %v", err)
	}
	var target *url.URL
	if cfg.Mode == "reverse" {
		target, err = url.Parse(cfg.TargetURL)
		if err != nil {
			fatalf("invalid -target %q: %v", cfg.TargetURL, err)
		}
	}

	// Secrets from files win over their flag equivalents: an operator who
	// supplies both has clearly moved to the file, and silently preferring the
	// flag would leave the credential in ps while looking like it had been fixed.
	secretsFromFile := map[string]bool{}
	if *authPassFile != "" {
		v, err := SecretFromFileOrExit(*authPassFile, "-auth-pass-file")
		cfg.Password = v
		secretsFromFile["auth-pass"] = true
		_ = err
	}
	if *secretFile != "" {
		v, _ := SecretFromFileOrExit(*secretFile, "-secret-file")
		cfg.SecretKey = v
		secretsFromFile["secret"] = true
	}

	setFlagsExtra := map[string]bool{}

	ports, err := parsePorts(*connectPorts)
	if err != nil {
		fatalf("invalid -connect-ports: %v", err)
	}
	// Validate rules before anything else touches them: an unparseable rule set
	// must not reach the request path, and an operator needs to be told which
	// line is wrong rather than discovering it as unexpected traffic.
	if *policyFile != "" {
		data, err := os.ReadFile(*policyFile)
		if err != nil {
			fatalf("-policy-file: %v", err)
		}
		policyRules = append(policyRules, strings.Split(string(data), "\n")...)
	}
	if len(policyRules) > 0 {
		if err := cfg.SetPolicyRules(strings.Join(policyRules, "\n")); err != nil {
			fatalf("invalid policy rules: %v", err)
		}
		setFlagsExtra["policy-rule"] = true
	}

	pol := proxy.Policy{
		AllowPrivate: *allowPrivate,
		ConnectPorts: ports,
		// Read per request so rules changed at runtime take effect without a
		// restart, the same way credentials do.
		Rules: cfg.PolicyRuleSet,
	}

	cfg.Headers = headers
	cfg.LogLevel = logLevel

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	for k := range setFlagsExtra {
		setFlags[k] = true
	}
	cli := startupValues{
		logLevel:     logLevel,
		authEnabled:  cfg.AuthEnabled,
		username:     cfg.Username,
		password:     cfg.Password,
		proxyName:    cfg.ProxyName,
		proxyID:      cfg.ProxyID,
		statsEnabled: cfg.StatsEnabled,
	}
	for name := range secretsFromFile {
		setFlags[name] = true
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

	logger, err := config.NewLogger(os.Stdout, cfg.GetLogLevel(), logFormat)
	if err != nil {
		fatalf("failed to build logger: %v", err)
	}

	for _, w := range store.Warnings() {
		logger.Warn(w)
	}
	warnFlagSecrets(logger, set, secretsFromFile)
	for _, f := range []struct{ path, flag string }{
		{*authPassFile, "-auth-pass-file"}, {*secretFile, "-secret-file"},
	} {
		if f.path != "" && config.FileIsWorldReadable(f.path) {
			logger.Warnf("%s: %s is world-readable; restrict it to the proxy user (chmod 600)", f.flag, f.path)
		}
	}
	if config.CredentialsAtRisk(cfg) {
		logger.Warnf("Credentials will be stored unencrypted in %s; set -secret "+
			"(or PROXY_SECRET_KEY) to encrypt them at rest", *dbPath)
	}
	if store != nil {
		// Also rewrites credentials sealed by older builds under the current
		// key derivation.
		if err := store.Save(cfg); err != nil {
			logger.Errorf("Failed to persist config: %v", err)
		}
	}

	metrics, err := server.NewMetrics(prometheus.DefaultRegisterer)
	if err != nil {
		logger.Fatalf("Failed to register metrics: %v", err)
	}
	tracker := server.NewClientTracker()
	tracker.SetGauge(metrics.Clients)
	stats := server.NewDomainStats()

	var handler http.Handler
	if cfg.Mode == "forward" {
		if !*allowPrivate {
			logger.Info("Refusing to proxy to loopback/private addresses; pass -allow-private to permit them")
		}
		logger.Infof("CONNECT allowed to ports %s", *connectPorts)
		h := proxy.NewForward(logger, cfg.GetHeadersForClient, pol)
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
	// One Router serves whatever it is given: with no Proxy it 404s unmatched
	// paths, and with no UI/API/Metrics it proxies everything. Splitting the
	// admin surface onto its own listener is therefore two values rather than a
	// mode flag threaded through the dispatch.
	newRouter := func(proxy, ui, api, metricsH http.Handler) *server.Router {
		return &server.Router{
			Proxy:   proxy,
			UI:      ui,
			API:     api,
			Metrics: metricsH,
			// Consulted per request, so credentials changed through the UI or
			// API take effect without a restart.
			Auth:   cfg.GetAuth,
			Logger: logger,
			// Configurable because in reverse mode this shadows a backend that
			// serves the same path.
			HealthPath:    *healthPath,
			MetricsPublic: *metricsPublic,
			AuthFailures:  metrics.AuthFailures,
		}
	}

	var mux, adminMux *server.Router
	if *adminAddr != "" {
		// The proxy port proxies everything, including paths that would
		// otherwise collide with the admin surface.
		mux = newRouter(handler, nil, nil, nil)
		adminMux = newRouter(nil, uiHandler, apiHandler, promhttp.Handler())
		logger.Info("Admin surface bound to its own listener",
			log.String("addr", *adminAddr))
	} else {
		mux = newRouter(handler, uiHandler, apiHandler, promhttp.Handler())
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
	if adminMux != nil {
		srv.AdminAddr = *adminAddr
		srv.AdminHandler = adminMux
		srv.AdminCertFile = *adminCert
		srv.AdminKeyFile = *adminKey
	}

	if err := srv.Start(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

// parsePorts turns a comma-separated port list into numbers.
func parsePorts(list string) ([]int, error) {
	var out []int
	for _, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		n, err := strconv.Atoi(field)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q is not a valid port", field)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports given")
	}
	return out, nil
}

// runHealthcheck probes the local health endpoint. It exists so the container
// image can declare a HEALTHCHECK without adding curl or wget to a slim base
// just to make one HTTP request.
func runHealthcheck(httpAddr, healthPath string) int {
	if healthPath == "" {
		fmt.Fprintln(os.Stderr, "healthcheck: -health-path is empty, nothing to probe")
		return 1
	}
	host, port, err := net.SplitHostPort(httpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: bad -http address %q: %v\n", httpAddr, err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + healthPath
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %d\n", url, resp.StatusCode)
		return 1
	}
	return 0
}

// SecretFromFileOrExit reads a secret file or terminates. A credential that
// cannot be read is not something to continue past: with -auth enabled an empty
// password is the fail-open case, so this refuses to start instead.
func SecretFromFileOrExit(path, flagName string) (string, error) {
	v, err := config.SecretFromFile(path)
	if err != nil {
		fatalf("%s: %v", flagName, err)
	}
	return v, nil
}

// warnFlagSecrets points out credentials that arrived by flag or environment
// rather than from a file. Both are readable by any local user — flags through
// /proc/<pid>/cmdline and `ps`, the environment through /proc/<pid>/environ.
func warnFlagSecrets(logger *log.Logger, set overrides, fromFile map[string]bool) {
	for _, s := range []struct{ flagName, envName, fileFlag string }{
		{"auth-pass", "PROXY_AUTH_PASS", "-auth-pass-file"},
		{"secret", "PROXY_SECRET_KEY", "-secret-file"},
	} {
		if fromFile[s.flagName] || !set.has(s.flagName, s.envName) {
			continue
		}
		logger.Warnf("credential supplied via -%s/%s is readable by any local user "+
			"(ps, /proc); prefer %s", s.flagName, s.envName, s.fileFlag)
	}
}

// policyFlags collects repeated -policy-rule values, preserving order. The
// order is the semantics here, so a map or a set would lose the meaning.
type policyFlags []string

func (p *policyFlags) String() string { return strings.Join(*p, "; ") }

func (p *policyFlags) Set(value string) error {
	*p = append(*p, value)
	return nil
}
