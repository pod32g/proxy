package main

import (
	"fmt"
	"os"

	"github.com/pod32g/proxy/internal/config"
	"gopkg.in/yaml.v3"
)

// effective renders the configuration the process would actually run under, as
// a config file that would reproduce it.
//
// Not a dump of internal state: a file. That is the point. This project's
// recurring failure has been "the configuration says one thing and the process
// does another" — a flag captured instead of read live (PROXY-67), a reload
// reporting settings it had not applied (PROXY-77), reverse mode logging a
// parent proxy it was not using (PROXY-81), a database read failure yielding an
// empty policy in silence (PROXY-94). Every one of those would have been
// visible in a minute to anyone who could ask the process what it thought its
// configuration was.
//
// Emitting the file form rather than a report also means the answer can be
// diffed against the file on disk, and fed back in.
func effective(s *startupFlags, cfg *config.Config, ports []int) *config.File {
	str := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	boolean := func(v bool) *bool {
		if !v {
			return nil
		}
		return &v
	}
	num := func(v int) *int {
		if v == 0 {
			return nil
		}
		return &v
	}

	f := &config.File{
		Mode:          str(cfg.Mode),
		Target:        str(cfg.TargetURL),
		HTTP:          str(cfg.HTTPAddr),
		HTTPS:         str(cfg.HTTPSAddr),
		Cert:          str(cfg.CertFile),
		Key:           str(cfg.KeyFile),
		DB:            str(*s.dbPath),
		Stats:         boolean(cfg.StatsEnabledState()),
		AllowPrivate:  boolean(*s.allowPrivate),
		ConnectPorts:  ports,
		HealthPath:    str(*s.healthPath),
		MetricsPublic: boolean(*s.metricsPublic),
		UpstreamHTTP2: str(*s.upstreamHTTP2),
	}
	name, id := cfg.GetIdentity()
	f.ProxyName, f.ProxyID = str(name), str(id)

	// Rule sets as the operator wrote them, which is what round-trips.
	f.Policy = str(cfg.PolicyRulesText())
	f.Clients = str(cfg.ClientRulesText())
	f.Quotas = str(cfg.QuotaText())
	f.HeaderRules = str(cfg.HeaderRulesText())
	if h := cfg.GetHeaders(); len(h) > 0 {
		f.Headers = h
	}

	// Credentials are named, never printed. Everything else here is safe to
	// paste into a ticket, and this is the one thing that would not be.
	enabled, user, pass := cfg.GetAuth()
	if enabled || user != "" {
		f.Auth = &config.AuthFile{Enabled: boolean(enabled), Username: str(user)}
		if pass != "" {
			f.Auth.Password = str("(set, not shown)")
		}
	}

	f.Log = &config.LogFile{Level: str(*s.logLevel), Format: str(*s.logFormat)}

	if *s.accessLog != "" || *s.accessLogFile != "" {
		f.AccessLog = &config.AccessLogFile{Format: str(*s.accessLog), File: str(*s.accessLogFile)}
	}
	if *s.adminAddr != "" || *s.adminCert != "" {
		f.Admin = &config.AdminFile{HTTP: str(*s.adminAddr), Cert: str(*s.adminCert), Key: str(*s.adminKey)}
	}
	if *s.otelEndpoint != "" {
		f.Tracing = &config.TracingFile{Endpoint: str(*s.otelEndpoint), Insecure: boolean(*s.otelInsecure), Sample: s.otelSample}
	}
	if *s.destMetrics {
		f.DestinationMetrics = &config.DestinationMetricsFile{Enabled: boolean(true), Top: num(*s.destTop)}
	}
	if *s.upstreamCA != "" || *s.upstreamCert != "" {
		f.UpstreamTLS = &config.UpstreamTLSFile{CA: str(*s.upstreamCA), Cert: str(*s.upstreamCert), Key: str(*s.upstreamKey)}
	}
	if p := cfg.UpstreamProxy(); p.Configured() {
		f.UpstreamProxy = &config.UpstreamProxyFile{URL: str(p.String()), Username: str(p.Username), NoProxy: str(p.BypassList())}
		if p.Password != "" {
			f.UpstreamProxy.Password = str("(set, not shown)")
		}
	}
	if *s.cacheSize != "" {
		f.Cache = &config.CacheFile{Size: str(*s.cacheSize), MaxEntry: str(*s.cacheMaxEntry)}
	}
	if *s.pacEnabled {
		f.PAC = &config.PACFile{Enabled: boolean(true), Address: str(*s.pacAddress), HintDirect: boolean(*s.pacHintDirect)}
	}
	if *s.maxTunnels != 0 || *s.maxPerClient != 0 || *s.tunnelIdle != 0 {
		var idle *string
		if *s.tunnelIdle != 0 {
			idle = str(s.tunnelIdle.String())
		}
		f.Tunnels = &config.TunnelsFile{Max: num(*s.maxTunnels), MaxPerClient: num(*s.maxPerClient), IdleTimeout: idle}
	}
	return f
}

// printEffectiveConfig writes the effective configuration and what about it
// cannot be changed without a restart, then exits.
func printEffectiveConfig(s *startupFlags, cfg *config.Config, ports []int, from *config.File) {
	out, err := yaml.Marshal(effective(s, cfg, ports))
	if err != nil {
		fatalf("rendering the effective configuration: %v", err)
	}
	fmt.Printf("# Effective configuration: flags, environment, %s and the stored\n"+
		"# settings, merged in that precedence. Credentials are named, not shown.\n%s",
		describeSource(from), out)

	fmt.Printf("\n# Settings that a reload cannot change; these need a restart:\n")
	for _, name := range config.RestartOnly {
		fmt.Printf("#   %s\n", name)
	}
	os.Exit(0)
}

func describeSource(from *config.File) string {
	if from == nil {
		return "no config file"
	}
	return "the config file"
}

// validateAndExit reports whether the configuration is usable, without starting
// anything and without touching the database.
//
// Everything before this point in main has already run: the file was parsed and
// validated, the rule sets were compiled, the enums were checked, and the
// resulting authentication state was judged. Reaching here *is* the answer, so
// this is a placement decision rather than a second implementation — a separate
// validator would be one more thing that can disagree with the real path.
func validateAndExit(path string, warnings []string) {
	where := path
	if where == "" {
		where = "flags and environment"
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	fmt.Printf("ok: %s is valid\n", where)
	os.Exit(0)
}

// deprecationNotes lists what an operator is using that they should not be,
// for -validate, which is where someone checks a file before rolling it out.
func deprecationNotes(set overrides) []string {
	var out []string
	for name, d := range deprecated {
		if set.flags[name] || set.envs[envNameFor(name)] {
			out = append(out, fmt.Sprintf("-%s is deprecated; use %s (%s)",
				name, d.instead, d.why))
		}
	}
	return out
}
