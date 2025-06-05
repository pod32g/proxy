package config

// Config holds the runtime configuration for the proxy server.
import "sync"

// Config holds the runtime configuration for the proxy server.
type Config struct {
	// Mode determines whether the proxy runs in "reverse" or "forward" mode.
	Mode      string
	TargetURL string
	HTTPAddr  string
	HTTPSAddr string
	CertFile  string
	KeyFile   string

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
