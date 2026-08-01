package config

import (
	"sync"

	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/quota"
)

// Listener is one bound address and the configuration that governs traffic
// arriving on it.
//
// Anything a listener does not set falls back to the global configuration, so a
// deployment that wants one policy everywhere writes no listener overrides at
// all and a deployment that wants an internal interface treated differently
// overrides only what differs.
//
// The rule sets are file-configured and swapped on reload. The UI and API
// continue to edit the *global* sets, which govern every listener that has no
// override of its own. Splitting the admin surface per listener is a larger
// change than this; having UI edits silently apply to some listeners and not
// others would be worse than an honest, documented split.
type Listener struct {
	Name string
	Addr string
	Cert string
	Key  string

	// Mode and Target default to the global ones when empty.
	Mode   string
	Target string

	AllowPrivate bool
	ConnectPorts []int

	// global supplies anything this listener does not override.
	global *Config

	mu          sync.RWMutex
	policyText  string
	policyRules *policy.RuleSet
	clientText  string
	clientRules *policy.ClientSet
	quotaText   string
	quotaSet    *quota.Set
}

// NewListener builds a listener that falls back to cfg for anything it does not
// override.
func NewListener(name, addr string, cfg *Config) *Listener {
	return &Listener{Name: name, Addr: addr, global: cfg}
}

// SetPolicyRules installs this listener's destination rules. An empty text
// clears the override and returns the listener to the global set.
func (l *Listener) SetPolicyRules(text string) error {
	set, err := policy.Parse(text)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.policyText, l.policyRules = text, set
	return nil
}

// SetClientRules installs this listener's client access table.
func (l *Listener) SetClientRules(text string) error {
	set, err := policy.ParseClients(text)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clientText, l.clientRules = text, set
	return nil
}

// SetQuotas installs this listener's quotas.
func (l *Listener) SetQuotas(text string) error {
	set, err := quota.Parse(text)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.quotaText, l.quotaSet = text, set
	return nil
}

// HasQuotaOverride reports whether this listener has its own quotas.
//
// It matters for more than bookkeeping: listeners without an override share the
// global limiter, so a global ceiling stays genuinely global rather than
// becoming that ceiling *per listener*. A listener that sets its own quotas gets
// its own buckets, which is what "different quotas here" has to mean.
func (l *Listener) HasQuotaOverride() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.quotaText != ""
}

// HasPolicyOverride reports whether this listener has its own destination rules.
func (l *Listener) HasPolicyOverride() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.policyText != ""
}

// DestinationRulesFor returns the destination rules in force for a client on
// this listener, resolved the same way the global path resolves them.
func (l *Listener) DestinationRulesFor(clientIP string) *policy.RuleSet {
	l.mu.RLock()
	clients, global := l.clientRules, l.policyRules
	hasPolicy, hasClients := l.policyText != "", l.clientText != ""
	l.mu.RUnlock()

	if !hasPolicy && !hasClients {
		return l.global.DestinationRulesFor(clientIP)
	}
	if !hasPolicy {
		global = l.global.PolicyRuleSet()
	}
	if !hasClients {
		// The client table is what scopes destination rules per client, so a
		// listener that overrides only destinations still honours the global
		// client-scoped sets.
		return l.global.ClientRuleSet().DestinationsFor(clientIP, global)
	}
	return clients.DestinationsFor(clientIP, global)
}

// ClientAllowed reports whether an address may use this listener.
func (l *Listener) ClientAllowed(ip string) (bool, string) {
	l.mu.RLock()
	set, has := l.clientRules, l.clientText != ""
	l.mu.RUnlock()
	if !has {
		return l.global.ClientAllowed(ip)
	}
	decision, rule := set.Match(ip)
	if decision != policy.Deny {
		return true, ""
	}
	if rule != nil {
		return false, rule.String()
	}
	return false, "default deny"
}

// QuotaSet returns the quotas in force on this listener.
func (l *Listener) QuotaSet() *quota.Set {
	l.mu.RLock()
	set, has := l.quotaSet, l.quotaText != ""
	l.mu.RUnlock()
	if !has {
		return l.global.QuotaSet()
	}
	return set
}

// ResolvedMode returns this listener's mode, or the global one.
func (l *Listener) ResolvedMode() string {
	if l.Mode != "" {
		return l.Mode
	}
	return l.global.Mode
}

// ResolvedTarget returns this listener's reverse-mode target, or the global one.
func (l *Listener) ResolvedTarget() string {
	if l.Target != "" {
		return l.Target
	}
	return l.global.TargetURL
}
