package config

// Config holds the runtime configuration for the proxy server.
type Config struct {
	TargetURL string
	HTTPAddr  string
	HTTPSAddr string
	CertFile  string
	KeyFile   string
}
