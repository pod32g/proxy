package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pod32g/proxy/internal/header"
	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/quota"
	"github.com/pod32g/proxy/internal/upstream"
	"gopkg.in/yaml.v3"
)

// File is the on-disk configuration.
//
// The yaml tags carry omitempty so -print-config emits a file rather than a
// schema: a page of `null` is harder to read than the settings that are
// actually in force, and harder to diff against what is on disk. omitempty
// affects marshalling only — decoding, and the KnownFields check that makes a
// misspelled key a startup error, are unchanged.
//
// Every field is a pointer or a slice so that "absent" is distinguishable from
// "set to the zero value". Without that distinction a file that says nothing
// about authentication would read as `enabled: false` and silently turn it off,
// which is the failure mode the precedence work in PROXY-11 exists to prevent.
type File struct {
	Mode   *string `yaml:"mode,omitempty"`
	Target *string `yaml:"target,omitempty"`
	HTTP   *string `yaml:"http,omitempty"`
	HTTPS  *string `yaml:"https,omitempty"`
	Cert   *string `yaml:"cert,omitempty"`
	Key    *string `yaml:"key,omitempty"`
	DB     *string `yaml:"db,omitempty"`

	Admin *AdminFile `yaml:"admin,omitempty"`

	Auth *AuthFile `yaml:"auth,omitempty"`

	Log *LogFile `yaml:"log,omitempty"`

	AccessLog *AccessLogFile `yaml:"access_log,omitempty"`

	Tracing *TracingFile `yaml:"tracing,omitempty"`

	DestinationMetrics *DestinationMetricsFile `yaml:"destination_metrics,omitempty"`

	// Cache is the shared response cache. Forward mode only; reverse mode
	// refuses to start with it rather than ignoring it.
	Cache *CacheFile `yaml:"cache,omitempty"`

	// UpstreamHTTP2 is how the proxy speaks HTTP/2 to origins: auto, off or h2c.
	UpstreamHTTP2 *string `yaml:"upstream_http2,omitempty"`

	// PAC serves a proxy auto-configuration file. Off unless asked for, and
	// unauthenticated by necessity — see internal/pac.
	PAC *PACFile `yaml:"pac,omitempty"`

	// Tunnels bounds how many hijacked connections may be held at once, and
	// how long an idle one survives. A request quota bounds the rate a client
	// acquires tunnels, not the stock it holds; see proxy.TunnelLimit.
	Tunnels *TunnelsFile `yaml:"tunnels,omitempty"`

	// UpstreamTLS is what the proxy presents and trusts when connecting
	// outward, distinct from cert/key above, which is what it presents to its
	// own clients.
	UpstreamTLS *UpstreamTLSFile `yaml:"upstream_tls,omitempty"`

	Stats         *bool   `yaml:"stats,omitempty"`
	AllowPrivate  *bool   `yaml:"allow_private,omitempty"`
	ConnectPorts  []int   `yaml:"connect_ports,omitempty"`
	HealthPath    *string `yaml:"health_path,omitempty"`
	MetricsPublic *bool   `yaml:"metrics_public,omitempty"`
	SecretFile    *string `yaml:"secret_file,omitempty"`
	Secret        *string `yaml:"secret,omitempty"`

	ProxyName *string `yaml:"proxy_name,omitempty"`
	ProxyID   *string `yaml:"proxy_id,omitempty"`

	Headers map[string]string `yaml:"headers,omitempty"`

	// Policy, Clients and Quotas take the same text the flags and the UI take,
	// so there is one syntax to learn rather than a YAML transliteration of an
	// ordered rule list — which would make the ordering, the whole point, an
	// accident of how the YAML happens to be written.
	Policy  *string `yaml:"policy,omitempty"`
	Clients *string `yaml:"clients,omitempty"`
	Quotas  *string `yaml:"quotas,omitempty"`

	// UpstreamProxy is a parent proxy all outbound traffic passes through.
	UpstreamProxy *UpstreamProxyFile `yaml:"upstream_proxy,omitempty"`

	// HeaderRules are the conditional form. The headers map above is the
	// unconditional one and keeps working; both are applied, map first.
	HeaderRules *string `yaml:"header_rules,omitempty"`

	// resolvedPassword is the password read from auth.password_file at load
	// time. Everything a file references is resolved before anything is
	// applied, so ApplyTo cannot fail partway and leave a configuration that
	// exists in no file. See LoadFile.
	resolvedPassword *string

	// Listeners are additional bound addresses, each with its own TLS material,
	// mode and rule sets. The top-level http/https settings remain exactly what
	// they were; these are in addition to them.
	Listeners []ListenerFile `yaml:"listeners,omitempty"`
}

// AdminFile is the `admin` block of a config file.
type AdminFile struct {
	HTTP *string `yaml:"http,omitempty"`
	Cert *string `yaml:"cert,omitempty"`
	Key  *string `yaml:"key,omitempty"`
}

// AuthFile is the `auth` block of a config file.
type AuthFile struct {
	Enabled      *bool   `yaml:"enabled,omitempty"`
	Username     *string `yaml:"username,omitempty"`
	Password     *string `yaml:"password,omitempty"`
	PasswordFile *string `yaml:"password_file,omitempty"`
}

// LogFile is the `log` block of a config file.
type LogFile struct {
	Level  *string `yaml:"level,omitempty"`
	Format *string `yaml:"format,omitempty"`
}

// AccessLogFile is the `access_log` block of a config file.
type AccessLogFile struct {
	Format *string `yaml:"format,omitempty"`
	File   *string `yaml:"file,omitempty"`
}

// TracingFile is the `tracing` block of a config file.
type TracingFile struct {
	Endpoint *string  `yaml:"endpoint,omitempty"`
	Insecure *bool    `yaml:"insecure,omitempty"`
	Sample   *float64 `yaml:"sample,omitempty"`
}

// DestinationMetricsFile is the `destination_metrics` block of a config file.
type DestinationMetricsFile struct {
	Enabled *bool `yaml:"enabled,omitempty"`
	Top     *int  `yaml:"top,omitempty"`
}

// CacheFile is the `cache` block of a config file.
type CacheFile struct {
	Size     *string `yaml:"size,omitempty"`
	MaxEntry *string `yaml:"max_entry,omitempty"`
}

// PACFile is the `pac` block of a config file.
type PACFile struct {
	Enabled    *bool   `yaml:"enabled,omitempty"`
	Address    *string `yaml:"address,omitempty"`
	HintDirect *bool   `yaml:"hint_direct,omitempty"`
}

// TunnelsFile is the `tunnels` block of a config file.
type TunnelsFile struct {
	Max          *int    `yaml:"max,omitempty"`
	MaxPerClient *int    `yaml:"max_per_client,omitempty"`
	IdleTimeout  *string `yaml:"idle_timeout,omitempty"`
}

// UpstreamTLSFile is the `upstream_tls` block of a config file.
type UpstreamTLSFile struct {
	CA   *string `yaml:"ca,omitempty"`
	Cert *string `yaml:"cert,omitempty"`
	Key  *string `yaml:"key,omitempty"`
}

// UpstreamProxyFile is the `upstream_proxy` block of a config file.
type UpstreamProxyFile struct {
	URL      *string `yaml:"url,omitempty"`
	Username *string `yaml:"username,omitempty"`
	Password *string `yaml:"password,omitempty"`
	NoProxy  *string `yaml:"no_proxy,omitempty"`
}

// ListenerFile is one entry in the listeners list. Anything it does not set
// falls back to the top-level configuration, so an entry that differs only in
// address and policy says only that.
type ListenerFile struct {
	Name string `yaml:"name,omitempty"`
	Addr string `yaml:"address,omitempty"`
	Cert string `yaml:"cert,omitempty"`
	Key  string `yaml:"key,omitempty"`

	Mode   *string `yaml:"mode,omitempty"`
	Target *string `yaml:"target,omitempty"`

	AllowPrivate *bool `yaml:"allow_private,omitempty"`
	ConnectPorts []int `yaml:"connect_ports,omitempty"`
	UpstreamTLS  *struct {
		CA   *string `yaml:"ca,omitempty"`
		Cert *string `yaml:"cert,omitempty"`
		Key  *string `yaml:"key,omitempty"`
	} `yaml:"upstream_tls,omitempty"`
	Policy  *string `yaml:"policy,omitempty"`
	Clients *string `yaml:"clients,omitempty"`
	Quotas  *string `yaml:"quotas,omitempty"`
}

// LoadFile reads and fully validates a configuration file.
//
// Validation happens here, before anything is installed, so a typo on line 40
// cannot leave the proxy running half the old policy and half the new. That is
// the same whole-set-or-nothing rule the policy API follows, and it is what
// makes a failed reload a no-op rather than a partial application.
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	// A misspelled key is a setting that silently does nothing, which is worse
	// than a startup error: the operator believes it is in effect.
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Everything the file points at is resolved here, before anything is
	// applied, because "validated in full before anything is applied" has to
	// include the filesystem. It did not: auth.password_file was read from
	// inside ApplyTo, after ten settings had already been written, so a
	// mistyped path applied auth.enabled without a password and the Router
	// then — correctly — refused every request, including the admin API that
	// would have fixed it.
	if f.Auth != nil && f.Auth.PasswordFile != nil {
		v, err := SecretFromFile(*f.Auth.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("%s: auth.password_file: %w", path, err)
		}
		f.resolvedPassword = &v
	}
	return &f, nil
}

func (f *File) validate() error {
	if f.Cache != nil {
		for name, v := range map[string]*string{
			"cache.size": f.Cache.Size, "cache.max_entry": f.Cache.MaxEntry,
		} {
			if v == nil || *v == "" {
				continue
			}
			if _, err := ParseBytes(*v); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		if f.Cache.Size != nil && *f.Cache.Size != "" &&
			f.Cache.MaxEntry != nil && *f.Cache.MaxEntry != "" {
			size, _ := ParseBytes(*f.Cache.Size)
			entry, _ := ParseBytes(*f.Cache.MaxEntry)
			if entry > size {
				return fmt.Errorf("cache.max_entry (%s) is larger than cache.size (%s)",
					*f.Cache.MaxEntry, *f.Cache.Size)
			}
		}
	}
	if f.Tunnels != nil {
		// An empty string is "not set", as it is for every other optional
		// string here — an example file that spells the key out with no value
		// should not be a startup error.
		if f.Tunnels.IdleTimeout != nil && *f.Tunnels.IdleTimeout != "" {
			if _, err := time.ParseDuration(*f.Tunnels.IdleTimeout); err != nil {
				return fmt.Errorf("tunnels.idle_timeout: %w", err)
			}
		}
		for name, v := range map[string]*int{
			"tunnels.max": f.Tunnels.Max, "tunnels.max_per_client": f.Tunnels.MaxPerClient,
		} {
			if v != nil && *v < 0 {
				return fmt.Errorf("%s: %d is negative; 0 is unlimited", name, *v)
			}
		}
	}
	if f.Mode != nil && *f.Mode != "forward" && *f.Mode != "reverse" {
		return fmt.Errorf("mode %q: want \"forward\" or \"reverse\"", *f.Mode)
	}
	if f.Log != nil {
		if f.Log.Level != nil {
			if _, err := ParseLogLevelStrict(*f.Log.Level); err != nil {
				return fmt.Errorf("log.level: %w", err)
			}
		}
		if f.Log.Format != nil {
			if _, err := ParseLogFormat(*f.Log.Format); err != nil {
				return fmt.Errorf("log.format: %w", err)
			}
		}
	}
	if f.Policy != nil {
		if _, err := policy.Parse(*f.Policy); err != nil {
			return fmt.Errorf("policy: %w", err)
		}
	}
	if f.Clients != nil {
		if _, err := policy.ParseClients(*f.Clients); err != nil {
			return fmt.Errorf("clients: %w", err)
		}
	}
	if f.Quotas != nil {
		if _, err := quota.Parse(*f.Quotas); err != nil {
			return fmt.Errorf("quotas: %w", err)
		}
	}
	if f.HeaderRules != nil {
		if _, err := header.Parse(*f.HeaderRules); err != nil {
			return fmt.Errorf("header_rules: %w", err)
		}
	}
	if f.UpstreamProxy != nil && f.UpstreamProxy.URL != nil {
		no := ""
		if f.UpstreamProxy.NoProxy != nil {
			no = *f.UpstreamProxy.NoProxy
		}
		if _, err := upstream.Parse(*f.UpstreamProxy.URL, no); err != nil {
			return fmt.Errorf("upstream_proxy: %w", err)
		}
	}
	for _, p := range f.ConnectPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("connect_ports: %d is not a valid port", p)
		}
	}
	if f.Tracing != nil && f.Tracing.Sample != nil {
		if *f.Tracing.Sample < 0 || *f.Tracing.Sample > 1 {
			return fmt.Errorf("tracing.sample: %v is outside 0..1", *f.Tracing.Sample)
		}
	}
	if f.Auth != nil && f.Auth.Password != nil && f.Auth.PasswordFile != nil {
		return fmt.Errorf("auth: set password or password_file, not both")
	}

	if u := f.upstreamTLS(); !u.Empty() {
		if err := u.Validate(); err != nil {
			return fmt.Errorf("upstream_tls: %w", err)
		}
	}

	names := map[string]bool{"http": true, "https": true, "admin": true}
	for i, l := range f.Listeners {
		where := fmt.Sprintf("listeners[%d]", i)
		if l.Name == "" || l.Addr == "" {
			return fmt.Errorf("%s: name and address are both required", where)
		}
		// Names appear in metrics labels and log fields, so a duplicate would
		// merge two listeners' traffic into one series under a name that no
		// longer identifies anything.
		if names[l.Name] {
			return fmt.Errorf("%s: listener name %q is already used", where, l.Name)
		}
		names[l.Name] = true
		if (l.Cert == "") != (l.Key == "") {
			return fmt.Errorf("%s: cert and key must be given together", where)
		}
		if l.Mode != nil && *l.Mode != "forward" && *l.Mode != "reverse" {
			return fmt.Errorf("%s: mode %q: want \"forward\" or \"reverse\"", where, *l.Mode)
		}
		if l.Mode != nil && *l.Mode == "reverse" && l.Target == nil && f.Target == nil {
			return fmt.Errorf("%s: reverse mode needs a target, here or at the top level", where)
		}
		for _, p := range l.ConnectPorts {
			if p < 1 || p > 65535 {
				return fmt.Errorf("%s: connect_ports: %d is not a valid port", where, p)
			}
		}
		if l.Policy != nil {
			if _, err := policy.Parse(*l.Policy); err != nil {
				return fmt.Errorf("%s: policy: %w", where, err)
			}
		}
		if l.Clients != nil {
			if _, err := policy.ParseClients(*l.Clients); err != nil {
				return fmt.Errorf("%s: clients: %w", where, err)
			}
		}
		if l.Quotas != nil {
			if _, err := quota.Parse(*l.Quotas); err != nil {
				return fmt.Errorf("%s: quotas: %w", where, err)
			}
		}
		if u := listenerUpstreamTLS(l); !u.Empty() {
			if err := u.Validate(); err != nil {
				return fmt.Errorf("%s: upstream_tls: %w", where, err)
			}
		}
	}
	return nil
}

// upstreamTLS reads the top-level outbound TLS material.
func (f *File) upstreamTLS() UpstreamTLS {
	var out UpstreamTLS
	if f == nil || f.UpstreamTLS == nil {
		return out
	}
	if f.UpstreamTLS.CA != nil {
		out.CAFile = *f.UpstreamTLS.CA
	}
	if f.UpstreamTLS.Cert != nil {
		out.CertFile = *f.UpstreamTLS.Cert
	}
	if f.UpstreamTLS.Key != nil {
		out.KeyFile = *f.UpstreamTLS.Key
	}
	return out
}

// UpstreamTLSConfig returns the top-level outbound TLS material.
func (f *File) UpstreamTLSConfig() UpstreamTLS { return f.upstreamTLS() }

func listenerUpstreamTLS(l ListenerFile) UpstreamTLS {
	var out UpstreamTLS
	if l.UpstreamTLS == nil {
		return out
	}
	if l.UpstreamTLS.CA != nil {
		out.CAFile = *l.UpstreamTLS.CA
	}
	if l.UpstreamTLS.Cert != nil {
		out.CertFile = *l.UpstreamTLS.Cert
	}
	if l.UpstreamTLS.Key != nil {
		out.KeyFile = *l.UpstreamTLS.Key
	}
	return out
}

// BuildListeners resolves the file's listener entries against the global
// configuration. Validation has already run, so nothing here can fail on a
// value the file supplied.
func (f *File) BuildListeners(cfg *Config, defaultAllowPrivate bool, defaultPorts []int) ([]*Listener, error) {
	if f == nil {
		return nil, nil
	}
	out := make([]*Listener, 0, len(f.Listeners))
	for _, lf := range f.Listeners {
		l := NewListener(lf.Name, lf.Addr, cfg)
		l.Cert, l.Key = lf.Cert, lf.Key
		if lf.Mode != nil {
			l.Mode = *lf.Mode
		}
		if lf.Target != nil {
			l.Target = *lf.Target
		}
		l.AllowPrivate = defaultAllowPrivate
		if lf.AllowPrivate != nil {
			l.AllowPrivate = *lf.AllowPrivate
		}
		l.ConnectPorts = defaultPorts
		if len(lf.ConnectPorts) > 0 {
			l.ConnectPorts = lf.ConnectPorts
		}
		l.UpstreamTLS = listenerUpstreamTLS(lf)
		if lf.Policy != nil {
			if err := l.SetPolicyRules(*lf.Policy); err != nil {
				return nil, err
			}
		}
		if lf.Clients != nil {
			if err := l.SetClientRules(*lf.Clients); err != nil {
				return nil, err
			}
		}
		if lf.Quotas != nil {
			if err := l.SetQuotas(*lf.Quotas); err != nil {
				return nil, err
			}
		}
		out = append(out, l)
	}
	return out, nil
}

// Password resolves the configured credential, reading the file when one is
// named. Returns ("", false) when the file says nothing about it.
func (f *File) Password() (string, bool, error) {
	if f.Auth == nil {
		return "", false, nil
	}
	// Resolved at load time when the file came from LoadFile, so a password
	// file that has gone missing since cannot fail an apply that is already
	// half done. A File built directly — in a test — still reads it here.
	if f.resolvedPassword != nil {
		return *f.resolvedPassword, true, nil
	}
	if f.Auth.PasswordFile != nil {
		v, err := SecretFromFile(*f.Auth.PasswordFile)
		if err != nil {
			return "", false, fmt.Errorf("auth.password_file: %w", err)
		}
		return v, true, nil
	}
	if f.Auth.Password != nil {
		return *f.Auth.Password, true, nil
	}
	return "", false, nil
}

// Live is the set of settings a reload can put into effect. They are read
// through locked accessors on every request, which is what makes changing them
// under concurrent traffic safe rather than merely likely to work.
//
// ApplyTo installs them. It returns the names of what it changed, so a reload
// can say what it did rather than claiming success in the abstract.
func (f *File) ApplyTo(cfg *Config) ([]string, error) {
	if f == nil {
		return nil, nil
	}
	// Everything that can fail is checked by Config.Apply before it writes
	// anything — including the resulting authentication state, which it can
	// judge better than this can because it sees the live values under the same
	// lock it will write through. A rejected update changes nothing.

	// One transaction, rather than a setter per field.
	//
	// Applied one at a time, a reader between two calls saw a configuration
	// that was half old and half new — and the policy and the client table are
	// composed on the read path, so a rule moved between them existed in
	// neither for 43% of a reload. See config.Update.
	u := Update{
		Stats:       f.Stats,
		ProxyName:   f.ProxyName,
		ProxyID:     f.ProxyID,
		Policy:      f.Policy,
		Clients:     f.Clients,
		Quotas:      f.Quotas,
		HeaderRules: f.HeaderRules,
		Headers:     f.Headers,
	}
	if f.Log != nil && f.Log.Level != nil {
		lvl, _ := ParseLogLevelStrict(*f.Log.Level)
		u.LogLevel = &lvl
	}
	if f.UpstreamProxy != nil && f.UpstreamProxy.URL != nil {
		up := &UpstreamUpdate{URL: *f.UpstreamProxy.URL}
		if f.UpstreamProxy.NoProxy != nil {
			up.NoProxy = *f.UpstreamProxy.NoProxy
		}
		up.Username = f.UpstreamProxy.Username
		up.Password = f.UpstreamProxy.Password
		u.Upstream = up
	}
	if f.Auth != nil {
		a := &AuthUpdate{Enabled: f.Auth.Enabled, Username: f.Auth.Username}
		if p, ok, err := f.Password(); err != nil {
			return nil, err
		} else if ok {
			a.Password = strPtr(p)
		}
		u.Auth = a
	}

	changed, err := cfg.Apply(u)
	if err != nil {
		return nil, err
	}
	sort.Strings(changed)
	return changed, nil
}

func sameHeaders(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Change is a setting a reload read but could not put into effect.
type Change struct {
	Setting string
	From    string
	To      string
}

// restartOnly is the single source for both the list of settings a reload
// cannot apply and the comparison that reports them.
//
// One table because there used to be two: a RestartOnly slice, quoted in the
// README, and a hand-written run of comparisons in RestartRequired. They had
// already drifted. Seven settings the list named were compared by nothing, and
// `listeners` and `upstream_tls` were in neither — so editing a listener's
// policy and sending SIGHUP applied nothing and warned about nothing, which is
// precisely the outcome RestartRequired exists to prevent.
//
// Every reader renders an absent value the same way whether the field is unset
// or its whole block is. Returning "" for a missing block and "(unset)" for a
// missing field inside a present one meant adding any tracing key at all
// reported a tracing.endpoint change that had not happened.
var restartOnly = []struct {
	name string
	read func(*File) string
}{
	{"mode", func(f *File) string { return deref(f.Mode) }},
	{"target", func(f *File) string { return deref(f.Target) }},
	{"http", func(f *File) string { return deref(f.HTTP) }},
	{"https", func(f *File) string { return deref(f.HTTPS) }},
	{"cert", func(f *File) string { return deref(f.Cert) }},
	{"key", func(f *File) string { return deref(f.Key) }},
	{"db", func(f *File) string { return deref(f.DB) }},
	{"health_path", func(f *File) string { return deref(f.HealthPath) }},
	{"secret", func(f *File) string { return redactedStr(f.Secret) }},
	{"secret_file", func(f *File) string { return deref(f.SecretFile) }},
	{"allow_private", func(f *File) string { return boolStr(f.AllowPrivate) }},
	{"metrics_public", func(f *File) string { return boolStr(f.MetricsPublic) }},
	{"connect_ports", func(f *File) string { return portsStr(f.ConnectPorts) }},

	{"admin.http", func(f *File) string {
		if f.Admin == nil {
			return deref(nil)
		}
		return deref(f.Admin.HTTP)
	}},
	{"admin.cert", func(f *File) string {
		if f.Admin == nil {
			return deref(nil)
		}
		return deref(f.Admin.Cert)
	}},
	{"admin.key", func(f *File) string {
		if f.Admin == nil {
			return deref(nil)
		}
		return deref(f.Admin.Key)
	}},

	{"log.format", func(f *File) string {
		if f.Log == nil {
			return deref(nil)
		}
		return deref(f.Log.Format)
	}},

	{"access_log.format", func(f *File) string {
		if f.AccessLog == nil {
			return deref(nil)
		}
		return deref(f.AccessLog.Format)
	}},
	{"access_log.file", func(f *File) string {
		if f.AccessLog == nil {
			return deref(nil)
		}
		return deref(f.AccessLog.File)
	}},

	{"tracing.endpoint", func(f *File) string {
		if f.Tracing == nil {
			return deref(nil)
		}
		return deref(f.Tracing.Endpoint)
	}},
	{"tracing.insecure", func(f *File) string {
		if f.Tracing == nil {
			return boolStr(nil)
		}
		return boolStr(f.Tracing.Insecure)
	}},
	{"tracing.sample", func(f *File) string {
		if f.Tracing == nil {
			return floatStr(nil)
		}
		return floatStr(f.Tracing.Sample)
	}},

	{"destination_metrics.enabled", func(f *File) string {
		if f.DestinationMetrics == nil {
			return boolStr(nil)
		}
		return boolStr(f.DestinationMetrics.Enabled)
	}},
	{"destination_metrics.top", func(f *File) string {
		if f.DestinationMetrics == nil {
			return intStr(nil)
		}
		return intStr(f.DestinationMetrics.Top)
	}},

	{"upstream_tls.ca", func(f *File) string {
		if f.UpstreamTLS == nil {
			return deref(nil)
		}
		return deref(f.UpstreamTLS.CA)
	}},
	{"upstream_tls.cert", func(f *File) string {
		if f.UpstreamTLS == nil {
			return deref(nil)
		}
		return deref(f.UpstreamTLS.Cert)
	}},
	{"upstream_tls.key", func(f *File) string {
		if f.UpstreamTLS == nil {
			return deref(nil)
		}
		return deref(f.UpstreamTLS.Key)
	}},

	{"cache.size", func(f *File) string {
		if f.Cache == nil {
			return deref(nil)
		}
		return deref(f.Cache.Size)
	}},
	{"cache.max_entry", func(f *File) string {
		if f.Cache == nil {
			return deref(nil)
		}
		return deref(f.Cache.MaxEntry)
	}},
	{"upstream_http2", func(f *File) string { return deref(f.UpstreamHTTP2) }},

	{"pac.enabled", func(f *File) string {
		if f.PAC == nil {
			return boolStr(nil)
		}
		return boolStr(f.PAC.Enabled)
	}},
	{"pac.address", func(f *File) string {
		if f.PAC == nil {
			return deref(nil)
		}
		return deref(f.PAC.Address)
	}},
	{"pac.hint_direct", func(f *File) string {
		if f.PAC == nil {
			return boolStr(nil)
		}
		return boolStr(f.PAC.HintDirect)
	}},

	{"tunnels.max", func(f *File) string {
		if f.Tunnels == nil {
			return intStr(nil)
		}
		return intStr(f.Tunnels.Max)
	}},
	{"tunnels.max_per_client", func(f *File) string {
		if f.Tunnels == nil {
			return intStr(nil)
		}
		return intStr(f.Tunnels.MaxPerClient)
	}},
	{"tunnels.idle_timeout", func(f *File) string {
		if f.Tunnels == nil {
			return deref(nil)
		}
		return deref(f.Tunnels.IdleTimeout)
	}},

	{"listeners", listenersStr},
}

// RestartOnly names the settings a reload cannot apply, for the documentation
// and for the error message. Derived from the table above rather than written
// out again, which is how the two came apart in the first place.
var RestartOnly = restartOnlyNames()

// Reloadable names the settings ApplyTo puts into effect.
//
// It exists so that Reloadable and RestartOnly together can be checked against
// the File struct itself: a field in neither is a setting the reload would
// silently ignore, which is what happened to `listeners` and `upstream_tls`.
// The test that walks the struct is what turns "every setting is either applied
// or reported" from an intention into a property, and it is the reason to
// tolerate a second list rather than just fixing the first.
var Reloadable = []string{
	"auth.enabled", "auth.password", "auth.password_file", "auth.username",
	"clients", "header_rules", "headers", "log.level", "policy",
	"proxy_id", "proxy_name", "quotas", "stats",
	"upstream_proxy.no_proxy", "upstream_proxy.password",
	"upstream_proxy.url", "upstream_proxy.username",
}

func restartOnlyNames() []string {
	out := make([]string, 0, len(restartOnly))
	for _, s := range restartOnly {
		out = append(out, s.name)
	}
	sort.Strings(out)
	return out
}

// RestartRequired reports settings that differ from the running configuration
// and cannot be changed without a restart.
//
// Reporting these is the point. A reload that quietly ignored half the file
// would leave a proxy whose configuration says one thing and whose behaviour
// says another, and nobody would find out until the next restart changed
// behaviour nobody asked for at a moment nobody chose.
func (f *File) RestartRequired(prev *File) []Change {
	if f == nil || prev == nil {
		return nil
	}
	var out []Change
	for _, s := range restartOnly {
		if before, after := s.read(prev), s.read(f); before != after {
			out = append(out, Change{s.name, before, after})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Setting < out[j].Setting })
	return out
}

// listenersStr renders the listener block so that any change to it is both
// detectable and legible in a warning. ListenerFile's yaml tags carry
// omitempty for this: without it the warning is mostly "null".
//
// Marshalled rather than hand-formatted, so a field added to ListenerFile later
// is covered without anyone remembering to extend this — which is the failure
// this whole table is fixing.
func listenersStr(f *File) string {
	if f == nil || len(f.Listeners) == 0 {
		return "(none)"
	}
	out, err := yaml.Marshal(f.Listeners)
	if err != nil {
		return fmt.Sprintf("(%d listeners)", len(f.Listeners))
	}
	return strings.Join(strings.Fields(string(out)), " ")
}

func deref(s *string) string {
	if s == nil {
		return "(unset)"
	}
	return *s
}

func floatStr(f *float64) string {
	if f == nil {
		return "(unset)"
	}
	return strconv.FormatFloat(*f, 'g', -1, 64)
}

func intStr(n *int) string {
	if n == nil {
		return "(unset)"
	}
	return strconv.Itoa(*n)
}

// redactedStr compares a secret without printing it. The comparison has to see
// the value; the warning must not.
func redactedStr(s *string) string {
	if s == nil {
		return "(unset)"
	}
	if *s == "" {
		return "(empty)"
	}
	return "(set:" + strconv.Itoa(len(*s)) + ")"
}

func boolStr(b *bool) string {
	if b == nil {
		return "(unset)"
	}
	return fmt.Sprintf("%t", *b)
}

func portsStr(p []int) string {
	if len(p) == 0 {
		return "(unset)"
	}
	parts := make([]string, len(p))
	for i, v := range p {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, ",")
}
