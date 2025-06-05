package config

// Config holds the runtime configuration for the proxy server.
type Config struct {
	// Mode determines whether the proxy runs in "reverse" or "forward" mode.
	Mode      string
	TargetURL string
	HTTPAddr  string
	HTTPSAddr string
	CertFile  string
	KeyFile   string
	Headers   map[string]string
}
