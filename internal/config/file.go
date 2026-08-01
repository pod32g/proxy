package config

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/quota"
	"gopkg.in/yaml.v3"
)

// File is the on-disk configuration.
//
// Every field is a pointer or a slice so that "absent" is distinguishable from
// "set to the zero value". Without that distinction a file that says nothing
// about authentication would read as `enabled: false` and silently turn it off,
// which is the failure mode the precedence work in PROXY-11 exists to prevent.
type File struct {
	Mode   *string `yaml:"mode"`
	Target *string `yaml:"target"`
	HTTP   *string `yaml:"http"`
	HTTPS  *string `yaml:"https"`
	Cert   *string `yaml:"cert"`
	Key    *string `yaml:"key"`
	DB     *string `yaml:"db"`

	Admin *struct {
		HTTP *string `yaml:"http"`
		Cert *string `yaml:"cert"`
		Key  *string `yaml:"key"`
	} `yaml:"admin"`

	Auth *struct {
		Enabled      *bool   `yaml:"enabled"`
		Username     *string `yaml:"username"`
		Password     *string `yaml:"password"`
		PasswordFile *string `yaml:"password_file"`
	} `yaml:"auth"`

	Log *struct {
		Level  *string `yaml:"level"`
		Format *string `yaml:"format"`
	} `yaml:"log"`

	AccessLog *struct {
		Format *string `yaml:"format"`
		File   *string `yaml:"file"`
	} `yaml:"access_log"`

	Tracing *struct {
		Endpoint *string  `yaml:"endpoint"`
		Insecure *bool    `yaml:"insecure"`
		Sample   *float64 `yaml:"sample"`
	} `yaml:"tracing"`

	DestinationMetrics *struct {
		Enabled *bool `yaml:"enabled"`
		Top     *int  `yaml:"top"`
	} `yaml:"destination_metrics"`

	Stats         *bool   `yaml:"stats"`
	AllowPrivate  *bool   `yaml:"allow_private"`
	ConnectPorts  []int   `yaml:"connect_ports"`
	HealthPath    *string `yaml:"health_path"`
	MetricsPublic *bool   `yaml:"metrics_public"`
	SecretFile    *string `yaml:"secret_file"`
	Secret        *string `yaml:"secret"`

	ProxyName *string `yaml:"proxy_name"`
	ProxyID   *string `yaml:"proxy_id"`

	Headers map[string]string `yaml:"headers"`

	// Policy, Clients and Quotas take the same text the flags and the UI take,
	// so there is one syntax to learn rather than a YAML transliteration of an
	// ordered rule list — which would make the ordering, the whole point, an
	// accident of how the YAML happens to be written.
	Policy  *string `yaml:"policy"`
	Clients *string `yaml:"clients"`
	Quotas  *string `yaml:"quotas"`
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
	return &f, nil
}

func (f *File) validate() error {
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
	return nil
}

// Password resolves the configured credential, reading the file when one is
// named. Returns ("", false) when the file says nothing about it.
func (f *File) Password() (string, bool, error) {
	if f.Auth == nil {
		return "", false, nil
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
	var changed []string
	note := func(name string) { changed = append(changed, name) }

	if f.Log != nil && f.Log.Level != nil {
		lvl, _ := ParseLogLevelStrict(*f.Log.Level)
		if lvl != cfg.GetLogLevel() {
			cfg.SetLogLevel(lvl)
			note("log.level")
		}
	}
	if f.Stats != nil && *f.Stats != cfg.StatsEnabledState() {
		cfg.SetStatsEnabled(*f.Stats)
		note("stats")
	}
	if f.ProxyName != nil || f.ProxyID != nil {
		name, id := cfg.GetIdentity()
		if f.ProxyName != nil && *f.ProxyName != name {
			cfg.SetProxyName(*f.ProxyName)
			note("proxy_name")
		}
		if f.ProxyID != nil && *f.ProxyID != id {
			cfg.SetProxyID(*f.ProxyID)
			note("proxy_id")
		}
	}
	if f.Policy != nil && *f.Policy != cfg.PolicyRulesText() {
		if err := cfg.SetPolicyRules(*f.Policy); err != nil {
			return changed, err
		}
		note("policy")
	}
	if f.Clients != nil && *f.Clients != cfg.ClientRulesText() {
		if err := cfg.SetClientRules(*f.Clients); err != nil {
			return changed, err
		}
		note("clients")
	}
	if f.Quotas != nil && *f.Quotas != cfg.QuotaText() {
		if err := cfg.SetQuotas(*f.Quotas); err != nil {
			return changed, err
		}
		note("quotas")
	}
	if f.Headers != nil {
		if !sameHeaders(cfg.GetHeaders(), f.Headers) {
			cfg.ReplaceHeaders(f.Headers)
			note("headers")
		}
	}
	if f.Auth != nil {
		enabled, user, pass := cfg.GetAuth()
		if f.Auth.Enabled != nil && *f.Auth.Enabled != enabled {
			cfg.SetAuthEnabled(*f.Auth.Enabled)
			note("auth.enabled")
		}
		newUser, newPass := user, pass
		if f.Auth.Username != nil {
			newUser = *f.Auth.Username
		}
		if p, ok, err := f.Password(); err != nil {
			return changed, err
		} else if ok {
			newPass = p
		}
		if newUser != user || newPass != pass {
			cfg.SetCredentials(newUser, newPass)
			// Named without the value, as everywhere else.
			note("auth.credentials")
		}
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
	cmp := func(name string, a, b *string) {
		if !sameStr(a, b) {
			out = append(out, Change{name, deref(a), deref(b)})
		}
	}
	cmp("mode", prev.Mode, f.Mode)
	cmp("target", prev.Target, f.Target)
	cmp("http", prev.HTTP, f.HTTP)
	cmp("https", prev.HTTPS, f.HTTPS)
	cmp("cert", prev.Cert, f.Cert)
	cmp("key", prev.Key, f.Key)
	cmp("db", prev.DB, f.DB)
	cmp("health_path", prev.HealthPath, f.HealthPath)
	cmp("secret_file", prev.SecretFile, f.SecretFile)

	if !sameBool(prev.AllowPrivate, f.AllowPrivate) {
		out = append(out, Change{"allow_private", boolStr(prev.AllowPrivate), boolStr(f.AllowPrivate)})
	}
	if !sameBool(prev.MetricsPublic, f.MetricsPublic) {
		out = append(out, Change{"metrics_public", boolStr(prev.MetricsPublic), boolStr(f.MetricsPublic)})
	}
	if !samePorts(prev.ConnectPorts, f.ConnectPorts) {
		out = append(out, Change{"connect_ports", portsStr(prev.ConnectPorts), portsStr(f.ConnectPorts)})
	}
	if prevAdmin, next := adminAddr(prev), adminAddr(f); prevAdmin != next {
		out = append(out, Change{"admin.http", prevAdmin, next})
	}
	if prevA, next := accessLogFormat(prev), accessLogFormat(f); prevA != next {
		out = append(out, Change{"access_log.format", prevA, next})
	}
	if prevT, next := tracingEndpoint(prev), tracingEndpoint(f); prevT != next {
		out = append(out, Change{"tracing.endpoint", prevT, next})
	}
	if prevL, next := logFormat(prev), logFormat(f); prevL != next {
		out = append(out, Change{"log.format", prevL, next})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Setting < out[j].Setting })
	return out
}

func sameStr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameBool(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func samePorts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func deref(s *string) string {
	if s == nil {
		return "(unset)"
	}
	return *s
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

func adminAddr(f *File) string {
	if f == nil || f.Admin == nil {
		return ""
	}
	return deref(f.Admin.HTTP)
}

func accessLogFormat(f *File) string {
	if f == nil || f.AccessLog == nil {
		return ""
	}
	return deref(f.AccessLog.Format)
}

func tracingEndpoint(f *File) string {
	if f == nil || f.Tracing == nil {
		return ""
	}
	return deref(f.Tracing.Endpoint)
}

func logFormat(f *File) string {
	if f == nil || f.Log == nil {
		return ""
	}
	return deref(f.Log.Format)
}

// RestartOnly names the settings a reload cannot apply, for the documentation
// and for the error message. Enumerated here rather than left for users to
// discover by finding that a change did nothing.
var RestartOnly = []string{
	"mode", "target", "http", "https", "cert", "key", "db",
	"admin.http", "admin.cert", "admin.key",
	"allow_private", "connect_ports", "health_path", "metrics_public",
	"log.format", "access_log.format", "access_log.file",
	"tracing.endpoint", "tracing.insecure", "tracing.sample",
	"destination_metrics.enabled", "destination_metrics.top",
	"secret", "secret_file",
}
