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

	Username    string
	Password    string
	AuthEnabled bool
	SecretKey   string

	LogLevel log.LogLevel

	Headers map[string]string

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

// GetAuth returns the current authentication settings.
func (c *Config) GetAuth() (bool, string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AuthEnabled, c.Username, c.Password
}
