package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pod32g/proxy/internal/api"
	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/proxy"
	"github.com/pod32g/proxy/internal/quota"
	"github.com/pod32g/proxy/internal/server"
	"github.com/pod32g/proxy/internal/tracing"
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
	var clientRules policyFlags
	flag.Var(&clientRules, "client-rule",
		"client access rule (e.g. \"allow 10.0.0.0/8\", \"deny 10.1.2.3\", \"default deny\"); repeatable, longest prefix wins")
	clientFile := flag.String("client-file", env.get("PROXY_CLIENT_FILE", ""),
		"file of client access rules, one per line")
	var quotaRules policyFlags
	flag.Var(&quotaRules, "quota-rule",
		"quota rule (e.g. \"global requests 500/s burst 1000\", \"client bytes 10MB/s\", \"client 10.0.0.0/8 requests 200/s\"); repeatable, unlimited by default")
	quotaFile := flag.String("quota-file", env.get("PROXY_QUOTA_FILE", ""),
		"file of quota rules, one per line")
	connectPorts := flag.String("connect-ports", env.get("PROXY_CONNECT_PORTS", "443"),
		"comma-separated ports CONNECT may tunnel to")
	healthPath := flag.String("health-path", env.get("PROXY_HEALTH_PATH", server.DefaultHealthPath),
		"path answered without authentication for liveness probes; empty disables it (in reverse mode it shadows the backend)")
	adminAddr := flag.String("admin-http", env.get("PROXY_ADMIN_ADDR", ""),
		"serve the UI, API and metrics on their own listener; when set they are not served on the proxy port")
	adminCert := flag.String("admin-cert", env.get("PROXY_ADMIN_CERT_FILE", ""), "TLS certificate for the admin listener")
	adminKey := flag.String("admin-key", env.get("PROXY_ADMIN_KEY_FILE", ""), "TLS key for the admin listener")
	destinationMetrics := flag.Bool("destination-metrics", env.get("PROXY_DESTINATION_METRICS", "") == "true",
		"export per-destination request counts, sampled from the bounded top-N table at scrape time; off by default because hostnames are client-controlled")
	topDestinations := flag.Int("destination-metrics-top", server.DefaultTopDestinations,
		"how many destinations -destination-metrics reports; this is the series count, so keep it small")
	metricsPublic := flag.Bool("metrics-public", env.get("PROXY_METRICS_PUBLIC", "") == "true",
		"serve /metrics without authentication so scrapers that send no credentials keep working")
	authPassFile := flag.String("auth-pass-file", env.get("PROXY_AUTH_PASS_FILE", ""),
		"file containing the basic-auth password; preferred over -auth-pass, which is visible in ps")
	secretFile := flag.String("secret-file", env.get("PROXY_SECRET_FILE", ""),
		"file containing the credential-encryption secret; preferred over -secret, which is visible in ps")
	healthcheck := flag.Bool("healthcheck", false,
		"probe the local health endpoint and exit 0 or 1 (used by the container HEALTHCHECK)")
	otelEndpoint := flag.String("otel-endpoint", env.get("PROXY_OTEL_ENDPOINT", ""),
		"OTLP/HTTP collector for traces, e.g. localhost:4318; empty disables tracing entirely")
	otelInsecure := flag.Bool("otel-insecure", env.get("PROXY_OTEL_INSECURE", "") == "true",
		"send traces over plain HTTP rather than TLS")
	otelSample := flag.Float64("otel-sample", 1.0,
		"fraction of traces to record, 0 to 1; a proxy sees every request its clients make")
	accessLogStr := flag.String("access-log", env.get("PROXY_ACCESS_LOG", "structured"),
		"access log format ("+strings.Join(server.AccessLogFormats, ", ")+")")
	accessLogFile := flag.String("access-log-file", env.get("PROXY_ACCESS_LOG_FILE", ""),
		"write the access log to this file instead of stdout, so access records and diagnostics can be routed separately")
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
	accessFormat, err := server.ParseAccessLogFormat(*accessLogStr)
	if err != nil {
		fatalf("invalid -access-log: %v", err)
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

	if *clientFile != "" {
		data, err := os.ReadFile(*clientFile)
		if err != nil {
			fatalf("-client-file: %v", err)
		}
		clientRules = append(clientRules, strings.Split(string(data), "\n")...)
	}
	if len(clientRules) > 0 {
		if err := cfg.SetClientRules(strings.Join(clientRules, "\n")); err != nil {
			fatalf("invalid client rules: %v", err)
		}
		setFlagsExtra["client-rule"] = true
	}

	if *quotaFile != "" {
		data, err := os.ReadFile(*quotaFile)
		if err != nil {
			fatalf("-quota-file: %v", err)
		}
		quotaRules = append(quotaRules, strings.Split(string(data), "\n")...)
	}
	if len(quotaRules) > 0 {
		if err := cfg.SetQuotas(strings.Join(quotaRules, "\n")); err != nil {
			fatalf("invalid quota rules: %v", err)
		}
		setFlagsExtra["quota-rule"] = true
	}

	pol := proxy.Policy{
		AllowPrivate: *allowPrivate,
		ConnectPorts: ports,
		// Read per request so rules changed at runtime take effect without a
		// restart, the same way credentials do.
		Rules: cfg.DestinationRulesFor,
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

	accessLog, closeAccessLog, err := newAccessLog(accessFormat, *accessLogFile, logFormat)
	if err != nil {
		fatalf("-access-log-file: %v", err)
	}
	defer closeAccessLog()

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
		// Startup is audited like any other change: flags and environment
		// variables genuinely do alter stored settings through reapply, and
		// "this value changed when the process restarted" is exactly the kind
		// of thing an investigation needs and would otherwise never find.
		if err := store.Save(cfg, config.Actor{Via: config.ViaStartup}); err != nil {
			logger.Errorf("Failed to persist config: %v", err)
		}
	}

	// Tracing is off unless an endpoint is given, and "off" means no tracer at
	// all rather than one that does nothing — the handler skips the work on a
	// nil check instead of calling into a no-op.
	tracer, err := tracing.Start(context.Background(), tracing.Config{
		Endpoint:    *otelEndpoint,
		Insecure:    *otelInsecure,
		ServiceName: cfg.ProxyName,
		SampleRatio: *otelSample,
	})
	if err != nil {
		fatalf("tracing: %v", err)
	}
	if tracer != nil {
		logger.Info("Tracing enabled",
			log.String("endpoint", *otelEndpoint),
			log.String("sample", strconv.FormatFloat(*otelSample, 'g', -1, 64)))
		// A batching exporter holds spans in memory, so without this flush the
		// last seconds of traces are lost on every restart — exactly the window
		// around a deployment anyone wants to see.
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), tracing.ShutdownTimeout)
			defer cancel()
			if err := tracer.Shutdown(ctx); err != nil {
				logger.Errorf("Flushing traces: %v", err)
			}
		}()
	}

	metrics, err := server.NewMetrics(prometheus.DefaultRegisterer)
	if err != nil {
		logger.Fatalf("Failed to register metrics: %v", err)
	}
	tracker := server.NewClientTracker()
	tracker.SetGauge(metrics.Clients)
	stats := server.NewDomainStats()

	// Off by default. Even a bounded set of hostnames is information some sites
	// do not want in their metrics store, where retention and access are not the
	// ones they chose for their access logs.
	if *destinationMetrics {
		if err := prometheus.DefaultRegisterer.Register(
			server.NewDestinationCollector(stats, *topDestinations)); err != nil {
			logger.Fatalf("Failed to register destination metrics: %v", err)
		}
		logger.Info("Destination metrics enabled",
			log.Int("series", *topDestinations),
			log.String("note", "sampled from the bounded top-N table; -stats must be on to populate it"))
	}

	// Read through a function so quotas changed in the UI or API take effect
	// without a restart, the same way credentials and policy rules do.
	limiter := quota.NewLimiter(cfg.QuotaSet)
	limiter.Rejected = func(s quota.Scope) { metrics.QuotaRejected.WithLabelValues(string(s)).Inc() }
	limiter.Tracked = func(n int) { metrics.QuotaClients.Set(float64(n)) }
	if set := cfg.QuotaSet(); !set.Empty() {
		logger.Info("Quotas active", log.String("rules", strings.ReplaceAll(set.String(), "\n", "; ")))
	}

	var handler http.Handler
	var forwardMode bool
	if cfg.Mode == "forward" {
		if !*allowPrivate {
			logger.Info("Refusing to proxy to loopback/private addresses; pass -allow-private to permit them")
		}
		logger.Infof("CONNECT allowed to ports %s", *connectPorts)
		forwardMode = true
		h := proxy.NewForward(logger, cfg.GetHeadersForClient, pol, proxy.Observer{
			Upstream: func(method string, d time.Duration) {
				metrics.UpstreamDuration.WithLabelValues(method).Observe(d.Seconds())
			},
			TunnelOpened: func() { metrics.ActiveTunnels.Inc() },
			TunnelClosed: func() { metrics.ActiveTunnels.Dec() },
			Denied:       func(scope string) { metrics.PolicyDecisions.WithLabelValues(scope).Inc() },
			// nil when tracing is off, which is what makes it free.
			Trace: tracer.Hook(),
		})
		handler = h
	} else {
		handler = proxy.New(target, logger, cfg.GetHeadersForClient)
	}
	handler = server.MetricsMiddleware(handler, metrics)
	// Accounting wraps outermost so it sees the connection before anything else
	// hijacks it: a CONNECT tunnel and a WebSocket upgrade both bypass the
	// ResponseWriter entirely, and they are the traffic both the byte quota and
	// the access log care about most. One pass feeds both.
	// Destinations are recorded from the completion record rather than at
	// request entry, so a request the proxy refused is not counted as traffic to
	// the host it was refused from. Recording on the way in let a client put
	// entries in the "busiest destinations" view using requests that never
	// succeeded, and let a malformed CONNECT target land a nonsense host there.
	//
	// Reverse mode is different and deliberately unchanged: the key is always
	// the configured target, a constant nothing can inject, so every request to
	// it is worth counting whether the backend answered or not.
	recordDestination := func(e server.Exchange) {
		if !cfg.StatsEnabledState() {
			return
		}
		if !forwardMode {
			stats.Record(server.HostOnly(target.Host))
			return
		}
		if e.Served {
			stats.Record(server.HostOnly(e.Host))
		}
	}

	handler = server.AccountingMiddleware(handler, server.Accounting{
		Charge: func(client string, in, out int64) {
			// The quota is charged the total — bytes cost the same whichever
			// way they went — while the metric keeps them apart, because
			// "which direction is saturated" is a question the total cannot
			// answer.
			limiter.Charge(client, in+out)
			if in > 0 {
				metrics.RelayedBytes.WithLabelValues("in").Add(float64(in))
			}
			if out > 0 {
				metrics.RelayedBytes.WithLabelValues("out").Add(float64(out))
			}
		},
		Completed: func(e server.Exchange) {
			recordDestination(e)
			if accessLog != nil {
				accessLog(e)
			}
		},
	})
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
			// Both consulted per request, so a rule or quota changed at runtime
			// applies to the next request rather than the next restart.
			ClientAllowed: cfg.ClientAllowed,
			// Adapted rather than passed directly so the server package does not
			// have to know the quota package exists.
			Quota: func(ip string) (bool, time.Duration, string) {
				ok, retryAfter, scope := limiter.Allow(ip)
				return ok, retryAfter, string(scope)
			},
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

// newAccessLog builds the access-log sink and a function to close it.
//
// The access log gets its own logger at INFO rather than sharing the process
// logger, so that -log-level does not silence it. An operator who raises the
// level to WARN to quieten diagnostics is not asking to stop recording what the
// proxy brokered, and losing the access log as a side effect of a logging tweak
// is the kind of gap discovered only when someone needs it. -access-log off is
// the one way to turn it off.
func newAccessLog(format, path, logFormat string) (func(server.Exchange), func(), error) {
	noop := func() {}
	if format == "off" {
		return nil, noop, nil
	}

	out := io.Writer(os.Stdout)
	closeFn := noop
	if path != "" {
		// 0600: an access log names every destination every client visited,
		// which is not something to leave world-readable.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, noop, err
		}
		out = &lockedWriter{w: f}
		closeFn = func() { f.Close() }
	} else if format == "combined" {
		out = &lockedWriter{w: os.Stdout}
	}

	if format == "combined" {
		return server.NewAccessLog(format, nil, out), closeFn, nil
	}
	accessLogger, err := config.NewLogger(out, log.INFO, logFormat)
	if err != nil {
		closeFn()
		return nil, noop, err
	}
	return server.NewAccessLog(format, accessLogger, nil), closeFn, nil
}

// lockedWriter serialises writes so concurrent requests cannot interleave
// within a line. Records arrive from every request goroutine and, for tunnels,
// from the goroutine that closes the connection.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
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
