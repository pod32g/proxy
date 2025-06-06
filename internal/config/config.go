package config

// Config holds the runtime configuration for the proxy server.
import (
	"sync"

	log "github.com/pod32g/simple-logger"
	"strings"
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
	DebugLogs    bool
	UltraDebug   bool
	SecretKey    string

	LogLevel log.LogLevel

	Headers       map[string]string
	ClientHeaders map[string]map[string]string

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
	out := make(map[string]string, len(c.Headers))
	for k, v := range c.Headers {
		out[k] = v
	}
	if ch, ok := c.ClientHeaders[client]; ok {
		for k, v := range ch {
			out[k] = v
		}
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

// ParseLogLevel converts a string to a log.LogLevel.
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

// SetStatsEnabled enables or disables statistics collection.
func (c *Config) SetStatsEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.StatsEnabled = enabled
}

// StatsEnabledState returns whether statistics are enabled.
func (c *Config) StatsEnabledState() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.StatsEnabled
}

// SetDebugLogs enables or disables debug request logging.
func (c *Config) SetDebugLogs(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.DebugLogs = enabled
}

// DebugLogsEnabledState returns whether debug logging is enabled.
func (c *Config) DebugLogsEnabledState() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.DebugLogs
}

// SetUltraDebug enables or disables ultra debug logging.
func (c *Config) SetUltraDebug(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UltraDebug = enabled
}

// UltraDebugEnabledState returns whether ultra debug logging is enabled.
func (c *Config) UltraDebugEnabledState() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UltraDebug
}

// GetAuth returns the current authentication settings.
func (c *Config) GetAuth() (bool, string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AuthEnabled, c.Username, c.Password
}
