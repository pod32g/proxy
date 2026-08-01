// Package upstream describes a parent proxy this proxy forwards through.
//
// In an egress-controlled network all outbound traffic has to pass through a
// parent. Without this the proxy talks to origins directly, which does not make
// it differently configured — it makes it unusable.
package upstream

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Proxy is a parent proxy and the destinations that bypass it.
type Proxy struct {
	// URL is the parent, e.g. http://proxy.corp:3128. Empty means no parent.
	URL *url.URL

	// Username and Password authenticate to the parent. Held apart from URL so
	// the URL can be logged and stored without them.
	Username string
	Password string

	// bypass are destinations reached directly, NO_PROXY style.
	bypass []bypassRule
}

// bypassRule is one NO_PROXY entry.
type bypassRule struct {
	// host is a suffix match: "example.com" covers "api.example.com".
	host string
	// net is set for CIDR entries.
	net *net.IPNet
	// all is set by "*", which disables the parent entirely.
	all bool
}

// Configured reports whether a parent is set.
func (p *Proxy) Configured() bool { return p != nil && p.URL != nil }

// Parse builds a parent from a URL and a NO_PROXY-style bypass list.
//
// Credentials may be in the URL, which is what people paste from an existing
// http_proxy setting, but they are lifted out of it immediately: the URL is
// logged and persisted, and a credential embedded in it would travel with it
// everywhere it goes.
func Parse(rawURL, noProxy string) (*Proxy, error) {
	if strings.TrimSpace(rawURL) == "" {
		return &Proxy{}, nil
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %q: %v", rawURL, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		// A bare "host:port" — the most likely thing anyone types, copied from
		// an http_proxy setting — parses with the host *as* the scheme and the
		// port as an opaque body. Reporting that as an unsupported scheme is
		// technically true and useless, so it is recognised and the corrected
		// form suggested. Anything without a scheme is the same mistake.
		if u.Scheme == "" || u.Opaque != "" {
			return nil, fmt.Errorf("upstream proxy %q: needs a scheme, e.g. http://%s", rawURL, rawURL)
		}
		return nil, fmt.Errorf("upstream proxy %q: unsupported scheme %q (want http or https)", rawURL, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("upstream proxy %q: no host", rawURL)
	}

	p := &Proxy{}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
		u.User = nil
	}
	p.URL = u

	for _, entry := range strings.Split(noProxy, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == "*" {
			p.bypass = append(p.bypass, bypassRule{all: true})
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			p.bypass = append(p.bypass, bypassRule{net: network})
			continue
		}
		// A leading dot is the traditional NO_PROXY spelling for "and
		// subdomains", and plain suffix matching covers both spellings.
		p.bypass = append(p.bypass, bypassRule{host: strings.ToLower(strings.TrimPrefix(entry, "."))})
	}
	return p, nil
}

// SetCredentials replaces the parent's credentials, for the persistence path.
func (p *Proxy) SetCredentials(user, pass string) {
	if p == nil {
		return
	}
	p.Username, p.Password = user, pass
}

// Bypass reports whether a destination should be reached directly.
//
// hostport may or may not carry a port; both forms occur, since CONNECT always
// has one and an absolute-form URL may not.
func (p *Proxy) Bypass(hostport string) bool {
	if !p.Configured() {
		// With no parent everything is direct, so everything "bypasses".
		return true
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip := net.ParseIP(host)

	for _, rule := range p.bypass {
		switch {
		case rule.all:
			return true
		case rule.net != nil:
			if ip != nil && rule.net.Contains(ip) {
				return true
			}
		case rule.host != "":
			if host == rule.host || strings.HasSuffix(host, "."+rule.host) {
				return true
			}
		}
	}
	return false
}

// Addr returns the parent's host:port, defaulting the port from the scheme.
func (p *Proxy) Addr() string {
	if !p.Configured() {
		return ""
	}
	if p.URL.Port() != "" {
		return p.URL.Host
	}
	if p.URL.Scheme == "https" {
		return net.JoinHostPort(p.URL.Hostname(), "443")
	}
	return net.JoinHostPort(p.URL.Hostname(), "80")
}

// AuthHeader returns the Proxy-Authorization value for the parent, or "".
func (p *Proxy) AuthHeader() string {
	if !p.Configured() || p.Username == "" {
		return ""
	}
	raw := p.Username + ":" + p.Password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

// String renders the parent without credentials, for logs and for the store.
func (p *Proxy) String() string {
	if !p.Configured() {
		return ""
	}
	return p.URL.String()
}

// BypassList renders the bypass entries, for round-tripping.
func (p *Proxy) BypassList() string {
	if !p.Configured() {
		return ""
	}
	parts := make([]string, 0, len(p.bypass))
	for _, r := range p.bypass {
		switch {
		case r.all:
			parts = append(parts, "*")
		case r.net != nil:
			parts = append(parts, r.net.String())
		default:
			parts = append(parts, r.host)
		}
	}
	return strings.Join(parts, ",")
}
