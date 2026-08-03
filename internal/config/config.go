package config

// Config holds the runtime configuration for the proxy server.
import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/pod32g/proxy/internal/header"
	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/quota"
	"github.com/pod32g/proxy/internal/upstream"
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

	// Client access table: who may use the proxy, and optionally a
	// destination rule set scoped to them.
	clientText  string
	clientRules *policy.ClientSet

	// Quotas: how much a client may push through, globally and per client.
	quotaText string
	quotaSet  *quota.Set

	// Parent proxy, if outbound traffic must pass through one.
	upstreamProxy *upstream.Proxy

	// Conditional header rules. The unconditional Headers map above remains
	// the UI's editing surface and is folded into the applied set, so the two
	// are one mechanism rather than two that have to be kept in step.
	headerRuleText string
	headerRules    *header.RuleSet

	// Prebuilt merged rule sets, rebuilt whenever anything feeding them
	// changes. The request path reads a pointer; it does not assemble one.
	//
	// Assembling per request cost ~578ns and 1.2KB of garbage, twice per
	// request — comparable to the access log, which was at least a measured and
	// deliberate cost. The policy, client and quota sets have always been
	// swapped wholesale on edit and read without allocation; header rules were
	// the one left rebuilding.
	builtHeaderRules   *header.RuleSet
	builtHeaderClients map[string]*header.RuleSet

	mu sync.RWMutex
}

// SetHeader adds or updates a header in the config in a thread-safe manner.
//
// Validated with the same function the rule parser uses. Without it the two
// ways of setting a header disagreed about what a header may contain, and the
// permissive one answered success for a value that then broke every request.
func (c *Config) SetHeader(name, value string) error {
	if err := header.Validate(name, value); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Headers == nil {
		c.Headers = make(map[string]string)
	}
	c.Headers[name] = value
	c.rebuildHeaderRulesLocked()
	return nil
}

// SetClientHeader sets a header for a specific client.
func (c *Config) SetClientHeader(client, name, value string) error {
	if err := header.Validate(name, value); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ClientHeaders == nil {
		c.ClientHeaders = make(map[string]map[string]string)
	}
	if c.ClientHeaders[client] == nil {
		c.ClientHeaders[client] = make(map[string]string)
	}
	c.ClientHeaders[client][name] = value
	c.rebuildHeaderRulesLocked()
	return nil
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
		c.rebuildHeaderRulesLocked()
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
	c.rebuildHeaderRulesLocked()
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
// SetAuth updates the authentication settings, refusing a combination that
// would take the proxy off the air.
//
// Enabling authentication with no credential makes the Router refuse every
// request — deliberately, since the alternative is passing traffic the operator
// asked to have gated. The trap is that the admin API is behind the same gate,
// so the change cannot be undone through the surface that made it. A file
// reload reached this state through a mistyped password path (PROXY-90); the
// API reaches it by sending {"enabled": true} with no credentials, which is one
// curl away.
func (c *Config) SetAuth(enabled bool, username, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	user, pass := c.Username, c.Password
	if username != "" {
		user = username
	}
	if password != "" {
		pass = password
	}
	if enabled && (user == "" || pass == "") {
		return fmt.Errorf("cannot enable authentication without a username and password: " +
			"the proxy would refuse every request, including this API")
	}
	c.AuthEnabled = enabled
	c.Username, c.Password = user, pass
	return nil
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

// SetClientRules parses and installs the client access table.
func (c *Config) SetClientRules(text string) error {
	set, err := policy.ParseClients(text)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientText = text
	c.clientRules = set
	return nil
}

// ClientRuleSet returns the active client table.
func (c *Config) ClientRuleSet() *policy.ClientSet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientRules
}

// ClientRulesText returns the client table as written.
func (c *Config) ClientRulesText() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientText
}

// SetUpstreamProxy parses and installs the parent proxy.
func (c *Config) SetUpstreamProxy(rawURL, noProxy string) error {
	p, err := upstream.Parse(rawURL, noProxy)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Credentials already set are kept when the URL carries none, so changing
	// the address does not silently drop the password.
	if p.Configured() && p.Username == "" && c.upstreamProxy != nil {
		p.SetCredentials(c.upstreamProxy.Username, c.upstreamProxy.Password)
	}
	c.upstreamProxy = p
	return nil
}

// SetUpstreamProxyCredentials replaces the parent's credentials, for the
// persistence path where they arrive separately from the URL.
func (c *Config) SetUpstreamProxyCredentials(user, pass string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Replaced, not edited. UpstreamProxy hands this pointer to every request,
	// so writing through it races every reader currently holding one.
	c.upstreamProxy = c.upstreamProxy.WithCredentials(user, pass)
}

// UpstreamProxy returns the configured parent, or nil.
func (c *Config) UpstreamProxy() *upstream.Proxy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.upstreamProxy
}

// UpstreamProxyURL returns the parent without credentials, for logs and the
// store. The credentials are persisted separately and sealed like the proxy's
// own, so this value is safe to write anywhere the URL belongs.
func (c *Config) UpstreamProxyURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.upstreamProxy.String()
}

// UpstreamProxyBypass returns the bypass list as written.
func (c *Config) UpstreamProxyBypass() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.upstreamProxy.BypassList()
}

// UpstreamProxyCredentials returns the parent's credentials.
func (c *Config) UpstreamProxyCredentials() (string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.upstreamProxy == nil {
		return "", ""
	}
	return c.upstreamProxy.Username, c.upstreamProxy.Password
}

// SetHeaderRules parses and installs the conditional header rules.
func (c *Config) SetHeaderRules(text string) error {
	set, err := header.Parse(text)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headerRuleText = text
	c.headerRules = set
	c.rebuildHeaderRulesLocked()
	return nil
}

// rebuildHeaderRulesLocked assembles the merged sets. Callers hold the write
// lock, and every mutation of Headers, ClientHeaders or the conditional rules
// must call it — a stale prebuilt set is worse than a slow one, because the UI
// would report a change that never took effect.
func (c *Config) rebuildHeaderRulesLocked() {
	build := func(client string) *header.RuleSet {
		base := make(map[string]string, len(c.Headers)+len(c.ClientHeaders[client]))
		for k, v := range c.Headers {
			base[k] = v
		}
		for k, v := range c.ClientHeaders[client] {
			base[k] = v
		}
		migrated := header.FromMap(base)
		switch {
		case c.headerRules.Empty():
			return migrated
		case migrated == nil:
			return c.headerRules
		}
		// The map's entries are the older, unconditional form and run first, so
		// a conditional rule can override one of them.
		out := &header.RuleSet{
			Rules: make([]header.Rule, 0, len(migrated.Rules)+len(c.headerRules.Rules)),
		}
		out.Rules = append(out.Rules, migrated.Rules...)
		out.Rules = append(out.Rules, c.headerRules.Rules...)
		return out
	}

	c.builtHeaderRules = build("")
	// Only clients with headers of their own need an entry; everyone else reads
	// the global set. Bounded by what an operator configured, not by traffic.
	if len(c.ClientHeaders) == 0 {
		c.builtHeaderClients = nil
		return
	}
	built := make(map[string]*header.RuleSet, len(c.ClientHeaders))
	for client := range c.ClientHeaders {
		built[client] = build(client)
	}
	c.builtHeaderClients = built
}

// HeaderRulesText returns the rules as written.
func (c *Config) HeaderRulesText() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.headerRuleText
}

// HeaderRules returns the rules in force for a client.
//
// A map lookup and a pointer, on the request path. The sets are assembled when
// the configuration changes, which is rare, rather than when a request arrives,
// which is not.
//
// Order is the contract documented on header.RuleSet.Apply: the unconditional
// entries run first, so a conditional rule can override one of them.
func (c *Config) HeaderRules(client string) *header.RuleSet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if set, ok := c.builtHeaderClients[client]; ok {
		return set
	}
	return c.builtHeaderRules
}

// SetQuotas parses and installs the quota configuration.
func (c *Config) SetQuotas(text string) error {
	set, err := quota.Parse(text)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.quotaText = text
	c.quotaSet = set
	return nil
}

// QuotaSet returns the active quotas. Safe to call per request: the pointer is
// replaced wholesale rather than mutated.
func (c *Config) QuotaSet() *quota.Set {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.quotaSet
}

// QuotaText returns the quotas as written.
func (c *Config) QuotaText() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.quotaText
}

// ClientAllowed reports whether an address may use the proxy, naming the rule
// responsible so a refusal can say why.
func (c *Config) ClientAllowed(ip string) (bool, string) {
	set := c.ClientRuleSet()
	decision, rule := set.Match(ip)
	if decision != policy.Deny {
		return true, ""
	}
	if rule != nil {
		return false, rule.String()
	}
	return false, "default deny"
}

// DestinationRulesFor returns the destination rules in force for a client: the
// client's own set when it has one, otherwise the global set.
func (c *Config) DestinationRulesFor(clientIP string) *policy.RuleSet {
	c.mu.RLock()
	clients, global := c.clientRules, c.policyRules
	c.mu.RUnlock()
	if clients == nil {
		return global
	}
	return clients.DestinationsFor(clientIP, global)
}

// PolicyDecision is the result of a dry run: what the rules would do with a
// destination, and which rule decided it.
type PolicyDecision struct {
	Client      string `json:"client,omitempty"`
	Host        string `json:"host"`
	IP          string `json:"ip,omitempty"`
	ClientAllow bool   `json:"client_allowed"`
	ClientRule  string `json:"client_rule,omitempty"`
	Allowed     bool   `json:"allowed"`
	Rule        string `json:"rule,omitempty"`
	Reason      string `json:"reason"`
}

// EvaluatePolicy answers "would this be allowed, and by which rule". An ordered
// rule set that cannot be interrogated is guesswork in production, so this is
// the same evaluation the request path performs rather than a reimplementation
// that can drift from it.
//
// ip may be empty, in which case only rules decidable without DNS are applied
// and the answer says so.
func (c *Config) EvaluatePolicy(clientIP, host, ip string) PolicyDecision {
	out := PolicyDecision{Client: clientIP, Host: host, IP: ip}

	allowed, rule := c.ClientAllowed(clientIP)
	out.ClientAllow, out.ClientRule = allowed, rule
	if !allowed {
		out.Reason = "client refused: " + rule
		return out
	}

	var parsed net.IP
	if ip != "" {
		parsed = net.ParseIP(ip)
	}
	decision, matched := c.DestinationRulesFor(clientIP).Match(host, parsed)
	if matched != nil {
		out.Rule = matched.String()
	}
	switch decision {
	case policy.Allow:
		out.Allowed = true
		out.Reason = "allowed by rule: " + out.Rule
	case policy.Deny:
		out.Reason = "denied by rule: " + out.Rule
	default:
		// No rule decided. The request path would fall through to the
		// private-address default, which needs an address to evaluate.
		out.Allowed = true
		if ip == "" {
			out.Reason = "no rule decided without an address; supply ip= to evaluate cidr rules " +
				"and the private-address default"
		} else {
			out.Reason = "no rule matched; the private-address default applies"
		}
	}
	return out
}

// ReplaceHeaders swaps the global header set wholesale.
//
// A config file describes the headers that should exist, not a patch to apply,
// so merging would make a header impossible to remove by editing the file — the
// deleted entry would simply persist from the previous state.
func (c *Config) ReplaceHeaders(h map[string]string) {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Headers = out
	c.rebuildHeaderRulesLocked()
}
