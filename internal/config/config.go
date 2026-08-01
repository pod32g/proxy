package config

// Config holds the runtime configuration for the proxy server.
import (
	"fmt"
	"strings"
	"sync"

	"github.com/pod32g/proxy/internal/policy"
	log "github.com/pod32g/simple-logger"
)

// Config holds the runtime configuration for the proxy server.
type Config struct {
	// Mode determines whether the proxy runs in "reverse" or "forward" mode.
	Mode      string
	TargetURL string
	HTTPAddr  string
	HTTPSAddr string
	CertFile  string
	KeyFile   string

	Username     string
	Password     string
	AuthEnabled  bool
	StatsEnabled bool
	SecretKey    string

	ProxyName string
	ProxyID   string

	LogLevel log.LogLevel

	Headers       map[string]string
	ClientHeaders map[string]map[string]string

	// Destination policy. Held as both the text as written and its parsed
	// form; the text is what the operator sees and what round-trips to the
	// store, the parsed set is what the request path evaluates.
	policyText  string
	policyRules *policy.RuleSet

	mu sync.RWMutex
}

// SetHeader adds or updates a header in the config in a thread-safe manner.
func (c *Config) SetHeader(name, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Headers == nil {
		c.Headers = make(map[string]string)
	}
	c.Headers[name] = value
}

// SetClientHeader sets a header for a specific client.
func (c *Config) SetClientHeader(client, name, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ClientHeaders == nil {
		c.ClientHeaders = make(map[string]map[string]string)
	}
	if c.ClientHeaders[client] == nil {
		c.ClientHeaders[client] = make(map[string]string)
	}
	c.ClientHeaders[client][name] = value
}

// DeleteClientHeader removes a header for a specific client.
func (c *Config) DeleteClientHeader(client, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.ClientHeaders[client]; ok {
		delete(ch, name)
		if len(ch) == 0 {
			delete(c.ClientHeaders, client)
		}
	}
}

// GetHeadersForClient returns headers combining global and client-specific ones.
func (c *Config) GetHeadersForClient(client string) map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.Headers)+2)
	for k, v := range c.Headers {
		out[k] = v
	}
	if ch, ok := c.ClientHeaders[client]; ok {
		for k, v := range ch {
			out[k] = v
		}
	}
	if c.ProxyName != "" {
		out["X-Proxy-Name"] = c.ProxyName
	}
	if c.ProxyID != "" {
		out["X-Proxy-Id"] = c.ProxyID
	}
	return out
}

// GetAllClientHeaders returns a copy of all client-specific headers.
func (c *Config) GetAllClientHeaders() map[string]map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]map[string]string, len(c.ClientHeaders))
	for client, hdrs := range c.ClientHeaders {
		m := make(map[string]string, len(hdrs))
		for k, v := range hdrs {
			m[k] = v
		}
		out[client] = m
	}
	return out
}

// DeleteHeader removes a header from the config.
func (c *Config) DeleteHeader(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Headers, name)
}

// GetHeaders returns a copy of the configured headers.
func (c *Config) GetHeaders() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.Headers))
	for k, v := range c.Headers {
		out[k] = v
	}
	return out
}

// SetLogLevel updates the logging level.
func (c *Config) SetLogLevel(level log.LogLevel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LogLevel = level
}

// GetLogLevel returns the configured logging level.
func (c *Config) GetLogLevel() log.LogLevel {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.LogLevel
}

// LogLevels lists the accepted logging levels, in increasing severity.
var LogLevels = []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}

// ParseLogLevelStrict is ParseLogLevel with the silent fallback removed, so a
// typo surfaces at startup (or as a 400) instead of quietly becoming INFO.
func ParseLogLevelStrict(lvl string) (log.LogLevel, error) {
	up := strings.ToUpper(lvl)
	for _, known := range LogLevels {
		if up == known {
			return ParseLogLevel(up), nil
		}
	}
	return log.INFO, fmt.Errorf("invalid log level %q (want one of %s)", lvl, strings.Join(LogLevels, ", "))
}

// ParseLogLevel converts a string to a log.LogLevel, defaulting to INFO.
func ParseLogLevel(lvl string) log.LogLevel {
	switch strings.ToUpper(lvl) {
	case "DEBUG":
		return log.DEBUG
	case "INFO":
		return log.INFO
	case "WARN":
		return log.WARN
	case "ERROR":
		return log.ERROR
	case "FATAL":
		return log.FATAL
	default:
		return log.INFO
	}
}

// LevelString converts a log.LogLevel to its string representation.
func LevelString(level log.LogLevel) string {
	switch level {
	case log.DEBUG:
		return "DEBUG"
	case log.INFO:
		return "INFO"
	case log.WARN:
		return "WARN"
	case log.ERROR:
		return "ERROR"
	case log.FATAL:
		return "FATAL"
	default:
		return "INFO"
	}
}

// SetAuth updates the authentication settings. Empty username or password are ignored.
func (c *Config) SetAuth(enabled bool, username, password string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AuthEnabled = enabled
	if username != "" {
		c.Username = username
	}
	if password != "" {
		c.Password = password
	}
}

// SetAuthEnabled toggles authentication without touching the stored credentials.
func (c *Config) SetAuthEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AuthEnabled = enabled
}

// SetCredentials replaces the credentials verbatim, empty values included.
// SetAuth is the UI/API path and deliberately ignores blanks so "leave the
// password alone" works; this is the persistence path, where a blank stored
// value has to round-trip faithfully.
func (c *Config) SetCredentials(username, password string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Username = username
	c.Password = password
}

// SetStatsEnabled enables or disables statistics collection.
func (c *Config) SetStatsEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.StatsEnabled = enabled
}

// SetIdentity updates the proxy identity headers.
func (c *Config) SetIdentity(name, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if name != "" {
		c.ProxyName = name
	}
	if id != "" {
		c.ProxyID = id
	}
}

// SetProxyName replaces the proxy name verbatim, empty values included.
// SetIdentity ignores blanks for the UI's benefit; loading persisted state
// needs the literal value.
func (c *Config) SetProxyName(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ProxyName = name
}

// SetProxyID replaces the proxy id verbatim, empty values included.
func (c *Config) SetProxyID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ProxyID = id
}

// GetIdentity returns the configured proxy name and id.
func (c *Config) GetIdentity() (string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ProxyName, c.ProxyID
}

// StatsEnabledState returns whether statistics are enabled.
func (c *Config) StatsEnabledState() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.StatsEnabled
}

// GetAuth returns the current authentication settings.
func (c *Config) GetAuth() (bool, string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AuthEnabled, c.Username, c.Password
}

// SetPolicyRules parses and installs the destination rule set. The text is kept
// alongside the parsed form so it can be round-tripped to the store and shown
// in the UI exactly as written, comments included.
func (c *Config) SetPolicyRules(text string) error {
	set, err := policy.Parse(text)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyText = text
	c.policyRules = set
	return nil
}

// PolicyRuleSet returns the active rules. Safe to call per request: the pointer
// is replaced wholesale rather than mutated, so an in-flight evaluation keeps
// using the set it started with.
func (c *Config) PolicyRuleSet() *policy.RuleSet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policyRules
}

// PolicyRulesText returns the rules as written.
func (c *Config) PolicyRulesText() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policyText
}
