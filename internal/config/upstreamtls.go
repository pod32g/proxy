package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// UpstreamTLS is the TLS material the proxy uses when it connects *outward*.
//
// Distinct from the -cert/-key pair, which is what the proxy presents to its
// own clients. Conflating the two is easy and the consequences are quiet: a
// server certificate offered as a client certificate is simply not accepted,
// and the failure looks like an upstream problem.
type UpstreamTLS struct {
	// CAFile is an additional trust bundle, added to the system roots rather
	// than replacing them.
	CAFile string
	// CertFile and KeyFile are the client certificate presented to upstreams
	// that ask for one. Both or neither.
	CertFile string
	KeyFile  string
}

// Empty reports whether anything is configured.
func (u UpstreamTLS) Empty() bool {
	return u.CAFile == "" && u.CertFile == "" && u.KeyFile == ""
}

// Validate checks the combination without reading anything, for early rejection.
func (u UpstreamTLS) Validate() error {
	if (u.CertFile == "") != (u.KeyFile == "") {
		return fmt.Errorf("upstream cert and key must be given together")
	}
	return nil
}

// BuildTLSConfig loads the material and returns a client TLS configuration, or
// nil when nothing is configured.
//
// Everything is loaded here, at startup. A bundle that does not parse or a
// certificate that does not match its key is a configuration error, and
// discovering it on the first request means it arrives as a 502 on real traffic
// at a moment nobody chose, looking like an upstream fault rather than a
// mistake in a file.
//
// Note what this deliberately does not have: any way to skip verification. The
// pressure for one comes from exactly the situation CAFile solves — a private
// PKI with no way to trust it — and with that solved, a skip-verify flag would
// be a permanent silent downgrade for a problem that no longer exists. In a
// forward proxy it would also be indiscriminate: verification would be off for
// every destination at once, not just the internal one somebody was trying to
// reach.
func (u UpstreamTLS) BuildTLSConfig() (*tls.Config, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	if u.Empty() {
		return nil, nil
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if u.CAFile != "" {
		pem, err := os.ReadFile(u.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream CA bundle: %w", err)
		}
		// SystemCertPool returns a copy, so appending adds to the public roots
		// rather than replacing them. That is what an operator adding a private
		// CA almost always means — trust the internet *and* our own PKI — and
		// the other reading would silently break every public destination the
		// moment a private CA was configured.
		pool, err := x509.SystemCertPool()
		if err != nil {
			// Some platforms have no system pool at all. Starting from empty is
			// the honest fallback, but it narrows trust to the given bundle, so
			// it must not happen quietly.
			return nil, fmt.Errorf("reading the system trust store to extend it: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream CA bundle %s contains no usable certificates", u.CAFile)
		}
		cfg.RootCAs = pool
	}

	if u.CertFile != "" {
		pair, err := tls.LoadX509KeyPair(u.CertFile, u.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// Describe renders what is configured, for the startup log. Presenting a client
// certificate is a fact worth seeing at boot: if the upstream stops accepting
// it, knowing one was offered at all is the first thing to establish.
func (u UpstreamTLS) Describe() string {
	switch {
	case u.CAFile != "" && u.CertFile != "":
		return "custom CA bundle and client certificate"
	case u.CAFile != "":
		return "custom CA bundle"
	case u.CertFile != "":
		return "client certificate"
	default:
		return "system trust store"
	}
}
