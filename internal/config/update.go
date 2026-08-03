package config

import (
	"fmt"

	"github.com/pod32g/proxy/internal/header"
	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/quota"
	"github.com/pod32g/proxy/internal/upstream"
	log "github.com/pod32g/simple-logger"
)

// Update is a set of configuration changes applied as one.
//
// It exists because applying them one at a time is not the same thing. The
// individual setters are each correctly locked, and no read is torn — but
// between two setter calls the live configuration is half old and half new, and
// several settings are only meaningful in pairs.
//
// The destination policy and the client table are composed by
// ClientSet.DestinationsFor, so a rule moved from one to the other exists in
// neither during the gap. Measured on the ordinary edit that does exactly that
// — moving a deny out of the global policy into a client-scoped set — 43% of
// evaluations during a continuous reload allowed a destination that both the
// old and the new configuration deny. Not a narrow window: the gap between two
// setter calls is enormous next to a policy evaluation.
//
// The parent proxy and its credentials are the same defect on two values that
// are never separate, and 48% of reads during a rotation saw one parent's
// address with another's credentials.
//
// A nil pointer means "leave this alone", which is the same convention File
// uses, so an absent setting is distinguishable from one set to its zero value.
type Update struct {
	LogLevel  *log.LogLevel
	Stats     *bool
	ProxyName *string
	ProxyID   *string

	// Policy and Clients are composed on the read path and must move together.
	Policy      *string
	Clients     *string
	Quotas      *string
	HeaderRules *string
	// Headers replaces the unconditional map wholesale. Nil leaves it alone.
	Headers map[string]string

	Upstream *UpstreamUpdate
	Auth     *AuthUpdate
}

// UpstreamUpdate carries a parent and its credentials, which are one thing.
type UpstreamUpdate struct {
	URL     string
	NoProxy string
	// Username and Password are nil to keep whatever is set, so changing the
	// address does not silently drop the password.
	Username *string
	Password *string
}

// AuthUpdate carries the authentication settings, which are checked together:
// enabling without a credential takes the proxy off the air.
type AuthUpdate struct {
	Enabled  *bool
	Username *string
	Password *string
}

// Apply installs every change under one write lock, and reports which settings
// it altered.
//
// A reader sees all of them or none. Everything that can fail is done before
// the lock is taken, so a rejected update changes nothing — the same property
// PROXY-90 established for a reload that cannot be applied, extended to one
// that can.
func (c *Config) Apply(u Update) ([]string, error) {
	// Phase one: parse and validate. No state is touched, and an error here
	// leaves the running configuration exactly as it was.
	var (
		policyRules *policy.RuleSet
		clientRules *policy.ClientSet
		quotaSet    *quota.Set
		headerRules *header.RuleSet
		parent      *upstream.Proxy
		err         error
	)
	if u.Policy != nil {
		if policyRules, err = policy.Parse(*u.Policy); err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
	}
	if u.Clients != nil {
		if clientRules, err = policy.ParseClients(*u.Clients); err != nil {
			return nil, fmt.Errorf("clients: %w", err)
		}
	}
	if u.Quotas != nil {
		if quotaSet, err = quota.Parse(*u.Quotas); err != nil {
			return nil, fmt.Errorf("quotas: %w", err)
		}
	}
	if u.HeaderRules != nil {
		if headerRules, err = header.Parse(*u.HeaderRules); err != nil {
			return nil, fmt.Errorf("header_rules: %w", err)
		}
	}
	if u.Headers != nil {
		for name, value := range u.Headers {
			if err := header.Validate(name, value); err != nil {
				return nil, fmt.Errorf("headers: %w", err)
			}
		}
	}
	if u.Upstream != nil {
		if parent, err = upstream.Parse(u.Upstream.URL, u.Upstream.NoProxy); err != nil {
			return nil, err
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// The resulting authentication state is checked before anything is written,
	// because enabling authentication without a credential makes the Router
	// refuse every request — including the admin API that would undo it.
	if u.Auth != nil {
		enabled, user, pass := c.AuthEnabled, c.Username, c.Password
		if u.Auth.Enabled != nil {
			enabled = *u.Auth.Enabled
		}
		if u.Auth.Username != nil && *u.Auth.Username != "" {
			user = *u.Auth.Username
		}
		if u.Auth.Password != nil && *u.Auth.Password != "" {
			pass = *u.Auth.Password
		}
		if enabled && (user == "" || pass == "") {
			return nil, fmt.Errorf("cannot enable authentication without a username and password: " +
				"the proxy would refuse every request, including the admin API")
		}
	}

	var changed []string
	note := func(name string) { changed = append(changed, name) }

	if u.LogLevel != nil && *u.LogLevel != c.LogLevel {
		c.LogLevel = *u.LogLevel
		note("log.level")
	}
	if u.Stats != nil && *u.Stats != c.StatsEnabled {
		c.StatsEnabled = *u.Stats
		note("stats")
	}
	if u.ProxyName != nil && *u.ProxyName != c.ProxyName {
		c.ProxyName = *u.ProxyName
		note("proxy_name")
	}
	if u.ProxyID != nil && *u.ProxyID != c.ProxyID {
		c.ProxyID = *u.ProxyID
		note("proxy_id")
	}
	if u.Policy != nil && *u.Policy != c.policyText {
		c.policyText, c.policyRules = *u.Policy, policyRules
		note("policy")
	}
	if u.Clients != nil && *u.Clients != c.clientText {
		c.clientText, c.clientRules = *u.Clients, clientRules
		note("clients")
	}
	if u.Quotas != nil && *u.Quotas != c.quotaText {
		c.quotaText, c.quotaSet = *u.Quotas, quotaSet
		note("quotas")
	}
	if u.HeaderRules != nil && *u.HeaderRules != c.headerRuleText {
		c.headerRuleText, c.headerRules = *u.HeaderRules, headerRules
		note("header_rules")
	}
	if u.Headers != nil && !sameHeaders(c.Headers, u.Headers) {
		c.Headers = make(map[string]string, len(u.Headers))
		for k, v := range u.Headers {
			c.Headers[k] = v
		}
		note("headers")
	}
	if u.Upstream != nil {
		user, pass := "", ""
		if c.upstreamProxy != nil {
			user, pass = c.upstreamProxy.Username, c.upstreamProxy.Password
		}
		if u.Upstream.Username != nil {
			user = *u.Upstream.Username
		}
		if u.Upstream.Password != nil {
			pass = *u.Upstream.Password
		}
		// Address and credentials installed together, as one value. Set
		// separately, a rotation sent one parent's credentials to another for
		// roughly half of it.
		next := parent.WithCredentials(user, pass)
		if c.upstreamProxy == nil || next.String() != c.upstreamProxy.String() ||
			next.BypassList() != c.upstreamProxy.BypassList() {
			note("upstream_proxy")
		} else if user != c.upstreamProxy.Username || pass != c.upstreamProxy.Password {
			note("upstream_proxy.credentials")
		}
		c.upstreamProxy = next
	}
	if u.Auth != nil {
		if u.Auth.Enabled != nil && *u.Auth.Enabled != c.AuthEnabled {
			c.AuthEnabled = *u.Auth.Enabled
			note("auth.enabled")
		}
		user, pass := c.Username, c.Password
		if u.Auth.Username != nil && *u.Auth.Username != "" {
			user = *u.Auth.Username
		}
		if u.Auth.Password != nil && *u.Auth.Password != "" {
			pass = *u.Auth.Password
		}
		if user != c.Username || pass != c.Password {
			c.Username, c.Password = user, pass
			// Named without the value, as everywhere else.
			note("auth.credentials")
		}
	}

	// Once, at the end: the merged header sets are derived from both the map
	// and the rules, so rebuilding after each would publish an intermediate.
	c.rebuildHeaderRulesLocked()
	return changed, nil
}

// strPtr is a small convenience for building an Update from values that are
// only sometimes present.
func strPtr(s string) *string { return &s }
