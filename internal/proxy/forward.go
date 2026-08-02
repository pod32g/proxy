package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pod32g/proxy/internal/cache"
	"github.com/pod32g/proxy/internal/header"
	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/reqid"
	"github.com/pod32g/proxy/internal/upstream"
	log "github.com/pod32g/simple-logger"
)

// Policy constrains where the proxy is willing to connect on a client's behalf.
// The zero value is the safe one: public destinations only, CONNECT to 443 only.
type Policy struct {
	// AllowPrivate permits loopback, private, link-local and unique-local
	// destinations. Off by default: a forward proxy takes destinations from
	// untrusted clients, so without this it is a ready-made SSRF pivot into
	// whatever the proxy host can reach — instance metadata, admin ports bound
	// to localhost, every in-cluster Service.
	AllowPrivate bool

	// ConnectPorts lists the ports CONNECT may tunnel to. Empty means 443 only.
	// An unrestricted CONNECT is a general-purpose TCP relay: usable for spam
	// through port 25, for scanning the internal network, and for laundering
	// arbitrary traffic through this host's address.
	ConnectPorts []int

	// Rules is an ordered allow/deny list applied to the destination, resolved
	// per client so a client-specific list can replace the global one. Nil
	// means no opinion, leaving AllowPrivate as the only constraint.
	Rules func(clientIP string) *policy.RuleSet

	// HeaderRules are the conditional header rules for a client, resolved per
	// request so edits take effect without a restart. Applied after the
	// hop-by-hop strip, which they cannot precede or undo.
	HeaderRules func(clientIP string) *header.RuleSet

	// Cache, when set, is a shared response cache. Nil disables caching
	// entirely — no lookup, no buffering, no storability check.
	Cache *cache.Cache

	// HTTP2 says how the proxy speaks HTTP/2 to origins. The zero value is
	// HTTP2Auto, which is what the default transport already did.
	HTTP2 UpstreamHTTP2

	// Upstream resolves the parent proxy every request is forwarded through
	// rather than dialling origins directly, or nil for none.
	//
	// A function, like Rules, HeaderRules and the quota set, because it is
	// reloadable: holding the value would mean a SIGHUP repointing the parent
	// reported success while traffic kept flowing to the old one — a config
	// file that says one thing while the process does another, which is the
	// failure the reload reporting exists to prevent.
	//
	// It also moves where the destination policy is enforced. See
	// checkDestination.
	Upstream func() *upstream.Proxy

	// UpstreamTLS configures outbound TLS: an additional trust bundle, a client
	// certificate, or both. Nil uses the system trust store.
	//
	// There is no way to disable verification here, deliberately. See
	// config.UpstreamTLS for why.
	UpstreamTLS *tls.Config
}

// ruleSet returns the rules in force for a client. It is a function so the set
// can be replaced at runtime without rebuilding the handler.
func (p Policy) ruleSet(clientIP string) *policy.RuleSet {
	if p.Rules == nil {
		return nil
	}
	return p.Rules(clientIP)
}

// clientKey carries the requesting client's address to the dialer, which needs
// it to pick the right destination rules.
type clientKey struct{}

// hostKey carries the requested hostname to ControlContext, which otherwise
// sees only the resolved address. Both facts are needed at once: evaluating
// domain and CIDR rules in separate passes would reorder the list.
type hostKey struct{}

// errDenied marks a policy refusal so the handlers can answer 403 rather than
// reporting it as an upstream fault. scope says which check refused, so a
// refusal can be attributed without parsing the message.
type errDenied struct {
	reason string
	scope  string
}

func (e *errDenied) Error() string { return e.reason }

func denied(err error) bool {
	var d *errDenied
	return errors.As(err, &d)
}

// deniedScope reports which check refused, or "" when the error is not a
// refusal.
func deniedScope(err error) string {
	var d *errDenied
	if errors.As(err, &d) {
		return d.scope
	}
	return ""
}

// Observer receives the facts only the handler is positioned to measure. Every
// field is optional; the zero value observes nothing.
type Observer struct {
	// Upstream is how long the origin took to respond. The middleware-level
	// histogram measures the whole exchange, so it cannot tell a slow origin
	// from a slow proxy — which is the question anyone actually has.
	Upstream func(method string, d time.Duration)
	// TunnelOpened and TunnelClosed bracket an established CONNECT tunnel.
	// Tunnels are long-lived and a request counter sees each one exactly once.
	TunnelOpened func()
	TunnelClosed func()
	// Denied records a refusal and which check made it.
	Denied func(scope string)
	// Protocol records what was actually negotiated with the origin. Before
	// this the answer was simply unavailable: resp.Proto was discarded.
	Protocol func(proto string)

	// Trace, when set, brackets the upstream round trip with a span. It is given
	// the outbound request and returns it, so a tracer can attach both a span
	// context and its propagation headers, plus a function to end the span.
	//
	// A plain function rather than an OpenTelemetry dependency in this package.
	// That is what keeps tracing genuinely optional: with tracing off the field
	// is nil and the handler does no tracing work at all, rather than calling
	// into a no-op implementation and paying for the call. No SDK type appears
	// on this path in either case.
	//
	// host and path are passed already sanitised — the path never carries a
	// query string, and url.URL keeps userinfo out of Host — so the tracer is
	// handed exactly the destination and nothing that could be a credential. It
	// reads no headers.
	Trace func(out *http.Request, host, path string) (*http.Request, func(status int, err error))
}

// trace starts a span if tracing is on. Both return values are safe to use when
// it is off.
func (o Observer) trace(out *http.Request, host, path string) (*http.Request, func(int, error)) {
	if o.Trace == nil {
		return out, func(int, error) {}
	}
	return o.Trace(out, host, path)
}

func (o Observer) upstream(method string, d time.Duration) {
	if o.Upstream != nil {
		o.Upstream(method, d)
	}
}

func (o Observer) protocol(proto string) {
	if o.Protocol != nil && proto != "" {
		o.Protocol(proto)
	}
}

func (o Observer) denied(scope string) {
	if o.Denied != nil && scope != "" {
		o.Denied(scope)
	}
}

func (o Observer) tunnelOpened() {
	if o.TunnelOpened != nil {
		o.TunnelOpened()
	}
}

func (o Observer) tunnelClosed() {
	if o.TunnelClosed != nil {
		o.TunnelClosed()
	}
}

// Refusal scopes. A closed set, so anything counting them has bounded
// cardinality by construction rather than by whatever gets passed in.
const (
	scopeDestination = "destination"
	scopeConnectPort = "connect-port"
	scopePrivateAddr = "private-address"
)

// DefaultConnectPorts is the allowlist used when none is configured.
var DefaultConnectPorts = []int{443}

func (p Policy) connectPorts() []int {
	if len(p.ConnectPorts) == 0 {
		return DefaultConnectPorts
	}
	return p.ConnectPorts
}

func (p Policy) connectAllowed(hostport string) error {
	_, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return fmt.Errorf("malformed CONNECT target %q", hostport)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("malformed CONNECT port %q", portStr)
	}
	for _, allowed := range p.connectPorts() {
		if port == allowed {
			return nil
		}
	}
	return fmt.Errorf("CONNECT to port %d is not permitted", port)
}

// blockedIP reports whether an address is off-limits under this policy.
func (p Policy) blockedIP(ip net.IP) bool {
	if p.AllowPrivate || ip == nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

// dialer builds a dialer that enforces the destination policy and gives up on
// unreachable hosts.
//
// The check lives in Control, which runs after DNS with the address actually
// about to be connected to. Checking the hostname instead would be defeated by
// a name that resolves to 127.0.0.1, and rechecking after resolution is the
// only way to close DNS rebinding.
func (p Policy) dialer() *net.Dialer {
	return &net.Dialer{
		// Without this, a blackholed destination hangs until the OS TCP
		// timeout — often over two minutes — pinning a goroutine and a
		// connection while the client waits with no response at all.
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		// ControlContext rather than Control, so the requested hostname can be
		// read off the context alongside the resolved address. This is the one
		// place both are known, and the ordered rule list needs both to be
		// evaluated in the order it was written.
		ControlContext: func(ctx context.Context, network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil
			}
			ip := net.ParseIP(host)
			requested, _ := ctx.Value(hostKey{}).(string)
			if requested == "" {
				requested = host
			}
			client, _ := ctx.Value(clientKey{}).(string)
			if decision, rule := p.ruleSet(client).Match(requested, ip); decision != policy.Undecided {
				if decision == policy.Deny {
					return &errDenied{
						reason: fmt.Sprintf("destination %s is not permitted by policy (%s)", requested, rule),
						scope:  scopeDestination,
					}
				}
				// An explicit allow overrides the private-address default:
				// naming an internal range in the rules is a deliberate act.
				return nil
			}
			if p.blockedIP(ip) {
				return &errDenied{
					reason: fmt.Sprintf("destination %s is not permitted (use -allow-private to allow it)", ip),
					scope:  scopePrivateAddr,
				}
			}
			return nil
		},
	}
}

// chained reports whether a destination goes through the parent proxy.
func (p Policy) chained(hostport string) bool {
	parent := p.parent()
	return parent.Configured() && !parent.Bypass(hostport)
}

// parent resolves the configured parent proxy, or nil.
func (p Policy) parent() *upstream.Proxy {
	if p.Upstream == nil {
		return nil
	}
	return p.Upstream()
}

// checkDestination evaluates the destination policy against the hostname the
// client asked for, before any connection is made.
//
// This exists because a parent proxy moves the ground under the post-DNS check.
// Normally the policy is enforced in ControlContext, on the address about to be
// connected to, which is what closes DNS rebinding: a name that resolves to
// 127.0.0.1 is caught because the check sees the resolved address.
//
// With a parent configured, the address about to be connected to is *the
// parent* — the same address for every request. Evaluating the rules there
// would match them against the parent's IP, so "allow domain example.com; deny
// all" would stop meaning what it says and nothing in the logs would show it.
// That is a silent, total bypass of every destination control, so with a parent
// the check moves to the requested hostname.
//
// What that costs is worth naming rather than glossing: the rebinding
// protection and the private-address default both concern where *this host*
// connects, and with a parent it no longer resolves or reaches the destination
// at all. Those are the parent's problem now, and the README says so.
func (p Policy) checkDestination(client, hostport string) error {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	// Resolved once: ruleSet may be a function reading live configuration, and
	// calling it twice could see two different sets mid-reload. It also returns
	// nil when no rules are configured, which Match handles but a field read
	// would not.
	set := p.ruleSet(client)
	decision, rule := set.Match(host, nil)
	if decision == policy.Deny {
		return &errDenied{
			reason: fmt.Sprintf("destination %s is not permitted by policy (%s)", host, rule),
			scope:  scopeDestination,
		}
	}
	if decision == policy.Undecided && set != nil && set.Default == policy.Deny {
		return &errDenied{
			reason: fmt.Sprintf("destination %s is not permitted by policy (default deny)", host),
			scope:  scopeDestination,
		}
	}
	return nil
}

// dialContext wraps the dialer so the hostname reaches ControlContext, and so
// an unambiguous denial can be answered without a DNS lookup or a dial.
func (p Policy) dialContext(d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		client, _ := ctx.Value(clientKey{}).(string)
		if decision, rule := p.ruleSet(client).Match(host, nil); decision == policy.Deny {
			return nil, &errDenied{
				reason: fmt.Sprintf("destination %s is not permitted by policy (%s)", host, rule),
				scope:  scopeDestination,
			}
		}
		return d.DialContext(context.WithValue(ctx, hostKey{}, host), network, addr)
	}
}

// applyHeaderRules runs the configured rules over a header set.
//
// It is called after removeHopByHop, never before. The strip is what keeps the
// proxy RFC-compliant and stops a client's credentials reaching every origin it
// visits; a rule that ran first could only be undone by it, and one that could
// run after and re-add a stripped header is rejected when it is written.
func applyHeaderRules(pol Policy, h http.Header, dir header.Direction, client, host string) {
	if pol.HeaderRules == nil {
		return
	}
	// No address: cidr conditions read as not matching, the same conservative
	// answer the destination policy gives before DNS.
	pol.HeaderRules(client).Apply(h, dir, hostOnly(host), nil)
}

// hostOnly strips a port from an authority so a domain condition matches what
// an operator would write.
func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

// setRequestID puts the exchange's identifier on an outbound request, so the
// origin's logs and ours name the same exchange. A client that supplied its own
// usable id sees that one propagate; anything unusable was replaced upstream of
// here, so what goes out is always sanitised.
func setRequestID(out *http.Request) {
	if id := reqid.FromContext(out.Context()); id != "" {
		out.Header.Set(reqid.Header, id)
	}
}

// withClient tags a request context with the client address so the dialer can
// resolve that client's rules.
func withClient(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientKey{}, clientIP(r.RemoteAddr)))
}

// clientIP strips the ephemeral source port from a RemoteAddr. Header rules are
// configured against an address an operator can see and type, and RemoteAddr is
// "IP:port" with a port that changes every connection — so keying the lookup on
// it directly means a client rule can never match.
func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// NewForward creates a forward proxy handler. It supports HTTPS via CONNECT
// without requiring TLS certificates. The headers function returns the headers
// that should be added to outbound requests and receives the client address.
// The observer is optional and variadic rather than a fourth parameter: it is
// pure instrumentation, and every call site that does not measure anything would
// otherwise have to name a zero value.
func NewForward(logger *log.Logger, headers func(string) map[string]string, pol Policy, observer ...Observer) http.Handler {
	var obs Observer
	if len(observer) > 0 {
		obs = observer[0]
	}
	dialer := pol.dialer()
	// Two transports. The h2 setting governs ordinary requests; upgrades are
	// pinned to HTTP/1.1 because the protocol requires it. CONNECT uses
	// neither — it dials for itself.
	//
	// The parent-proxy hook lives on the ordinary transport for the same
	// reason: it makes the request to the parent rather than the origin, which
	// a hijacked tunnel cannot do.
	transport, upgradeTransport, h2Transport := pol.buildTransport(dialer)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			logger.Debugf("CONNECT request %s", r.Host)
			if err := pol.connectAllowed(r.Host); err != nil {
				logger.Warnf("Refused CONNECT: %v", err)
				obs.denied(scopeConnectPort)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			handleConnect(w, withClient(r), logger, pol, dialer, obs)
			return
		}
		logger.Debugf("Forward proxy request %s %s", r.Method, sanitizedURL(r.URL))
		if r.URL.Scheme == "" || r.URL.Host == "" {
			logger.Error("Invalid request URL: missing scheme or host")
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		// Upgrade is hop-by-hop, so a compliant proxy consumes it and must
		// re-issue it deliberately to support one. Without this branch the
		// strip below removes the handshake and a ws:// request comes back as
		// an ordinary response — quietly, which is the worst part.
		if proto := requestedUpgrade(r.Header); proto != "" {
			handleUpgrade(w, r, upgradeTransport, headers, logger, proto, obs, pol)
			return
		}
		// A fresh hit answers here, before any of the outbound work.
		// Response rules run on the way out, so a hit carries exactly the headers
		// a miss would and a rule change reaches cached entries immediately.
		rewrite := func(h http.Header) {
			applyHeaderRules(pol, h, header.Response, clientIP(r.RemoteAddr), r.URL.Host)
		}
		hit, cached := serveFromCache(w, r, pol.Cache)
		if hit {
			writeEntry(w, cached, "HIT", rewrite)
			markServed(w)
			pol.Cache.Hit()
			return
		}
		stale := cached

		outReq := r.Clone(context.WithValue(r.Context(), clientKey{}, clientIP(r.RemoteAddr)))
		outReq.RequestURI = ""
		// r.Clone copies every header the client sent to the *proxy*, including
		// the credentials it used to authenticate to us. Strip the per-hop set
		// before it reaches the origin.
		removeHopByHop(outReq.Header)
		for k, v := range headers(clientIP(r.RemoteAddr)) {
			outReq.Header.Set(k, v)
		}
		// Carried to the origin so the exchange can be followed across the hop.
		// Set after the operator's headers so a stray -header cannot displace it.
		setRequestID(outReq)
		applyHeaderRules(pol, outReq.Header, header.Request, clientIP(r.RemoteAddr), r.URL.Host)
		// A stale entry with a validator becomes a conditional request, so the
		// origin can answer 304 with headers instead of a body.
		conditional(outReq, stale)

		// With a parent the transport connects to it, not to the destination,
		// so the destination check has to happen here instead of in the dialer.
		if pol.chained(r.URL.Host) {
			if err := pol.checkDestination(clientIP(r.RemoteAddr), r.URL.Host); err != nil {
				logger.Warn("Refused destination",
					log.String("host", r.URL.Host), log.String("client", clientIP(r.RemoteAddr)),
					log.String("request_id", reqid.FromContext(r.Context())))
				obs.denied(deniedScope(err))
				http.Error(w, "Destination not permitted", http.StatusForbidden)
				return
			}
			if auth := pol.parent().AuthHeader(); auth != "" {
				outReq.Header.Set("Proxy-Authorization", auth)
			}
		}

		// The span covers the round trip, matching the upstream histogram. The
		// request comes back carrying the span context and whatever propagation
		// headers the tracer adds, so the origin's own tracing joins this trace
		// rather than starting a new one.
		outReq, endSpan := obs.trace(outReq, r.URL.Host, r.URL.EscapedPath())

		// Timed around the round trip alone, which is the origin's contribution
		// and nothing else. The middleware histogram already covers the total.
		upstreamStart := time.Now()
		resp, err := pol.roundTripper(transport, h2Transport, outReq).RoundTrip(outReq)
		obs.upstream(r.Method, time.Since(upstreamStart))
		if err != nil {
			// A policy rejection is the client asking for somewhere it is not
			// allowed to go. That is a refusal, not an upstream fault, and
			// logging it at ERROR would put routine enforcement in with real
			// failures.
			if denied(err) {
				logger.Warn("Refused destination",
					log.String("host", r.URL.Host), log.String("client", clientIP(r.RemoteAddr)),
					log.String("request_id", reqid.FromContext(r.Context())))
				obs.denied(deniedScope(err))
				endSpan(http.StatusForbidden, err)
				http.Error(w, "Destination not permitted", http.StatusForbidden)
				return
			}
			logger.Errorf("Upstream error: %v", err)
			endSpan(http.StatusBadGateway, err)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
			return
		}
		endSpan(resp.StatusCode, nil)
		markServed(w)
		// The negotiated protocol was previously discarded, so there was no way
		// to tell what had actually been spoken to an origin.
		obs.protocol(resp.Proto)
		if s, ok := w.(interface{ SetProtocol(string) }); ok {
			s.SetProtocol(resp.Proto)
		}
		defer resp.Body.Close()
		removeHopByHop(resp.Header)

		// A 304 against a stored entry means the entry is still good: refresh
		// its lifetime and serve it. That exchange cost headers rather than a
		// body, which is the entire point of holding a validator.
		if resp.StatusCode == http.StatusNotModified && stale != nil {
			// Refresh returns a *replacement*; the entry passed in may be being
			// written to another client right now and is never edited.
			serve := stale
			if ttl, ok := cache.TTL(resp); ok {
				serve = pol.Cache.Refresh(stale, resp, ttl)
			}
			pol.Cache.Revalidated()
			writeEntry(w, serve, "REVALIDATED", rewrite)
			return
		}

		// Stored before the response rules run, so the entry holds what the
		// origin sent rather than this proxy's rewrite of it. The rules are
		// applied to the outgoing copy below, and to a hit on the way out, so
		// changing a rule takes effect on cached entries immediately.
		body := storeResponse(r, resp, pol.Cache)
		applyHeaderRules(pol, resp.Header, header.Response, clientIP(r.RemoteAddr), r.URL.Host)
		copyHeader(w.Header(), resp.Header)
		if pol.Cache != nil {
			w.Header().Set("X-Cache", "MISS")
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, body)
	})
}

// requestedUpgrade returns the protocol a client is asking to switch to, or ""
// when the request is an ordinary one.
func requestedUpgrade(h http.Header) string {
	if !headerHasToken(h, "Connection", "upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

// headerHasToken reports whether a comma-separated header lists a token.
// Connection carries a list, so a plain equality check would miss
// "Connection: keep-alive, Upgrade".
func headerHasToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// servedSetter lets a handler report that a request actually reached a
// destination. The accounting layer cannot tell that from the status alone: an
// origin can answer 403 just as a policy refusal does.
type servedSetter interface{ SetServed() }

// markServed records that this exchange reached a destination.
func markServed(w http.ResponseWriter) {
	if s, ok := w.(servedSetter); ok {
		s.SetServed()
	}
}

// statusSetter lets a handler report a status it could not write through
// WriteHeader. A protocol switch is written straight to a hijacked connection,
// so without this the metrics middleware would record the exchange as a 200.
type statusSetter interface{ SetStatus(int) }

// handleUpgrade proxies a protocol switch — a WebSocket handshake, in practice.
//
// The upstream side needs no raw dialing: Go's transport hands back a 101
// response whose Body is an io.ReadWriteCloser over the same connection, so the
// destination policy and dial timeout on the transport still apply.
func handleUpgrade(
	w http.ResponseWriter, r *http.Request, transport *http.Transport,
	headers func(string) map[string]string, logger *log.Logger, proto string, obs Observer, pol Policy,
) {
	logger.Debugf("Upgrade request %s to %s", sanitizedURL(r.URL), proto)

	outReq := r.Clone(context.WithValue(r.Context(), clientKey{}, clientIP(r.RemoteAddr)))
	outReq.RequestURI = ""
	// Strip the per-hop set as usual, then put back exactly the two headers
	// that carry this handshake. Re-issuing them is the deliberate act RFC 7230
	// asks for; blanket-forwarding them would not be.
	removeHopByHop(outReq.Header)
	outReq.Header.Set("Connection", "Upgrade")
	outReq.Header.Set("Upgrade", proto)
	for k, v := range headers(clientIP(r.RemoteAddr)) {
		outReq.Header.Set(k, v)
	}
	setRequestID(outReq)
	applyHeaderRules(pol, outReq.Header, header.Request, clientIP(r.RemoteAddr), r.URL.Host)

	upstreamStart := time.Now()
	resp, err := transport.RoundTrip(outReq)
	obs.upstream(r.Method, time.Since(upstreamStart))
	if err != nil {
		if denied(err) {
			logger.Warn("Refused upgrade destination", log.String("host", r.URL.Host),
				log.String("request_id", reqid.FromContext(r.Context())))
			obs.denied(deniedScope(err))
			http.Error(w, "Destination not permitted", http.StatusForbidden)
			return
		}
		logger.Errorf("Upgrade upstream error: %v", err)
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}

	markServed(w)

	// The origin is entitled to decline. Anything but 101 is an ordinary
	// response and must be relayed as one rather than hijacked.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		removeHopByHop(resp.Header)
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		logger.Error("Upgrade succeeded upstream but the connection is not writable")
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		logger.Errorf("Upgrade hijack error: %v", err)
		return
	}

	// Replay the origin's 101 verbatim, headers included: the client needs
	// Sec-WebSocket-Accept and anything else the origin negotiated.
	var head bytes.Buffer
	fmt.Fprintf(&head, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	if err := resp.Header.Write(&head); err != nil {
		upstream.Close()
		clientConn.Close()
		return
	}
	head.WriteString("\r\n")
	if _, err := clientConn.Write(head.Bytes()); err != nil {
		upstream.Close()
		clientConn.Close()
		return
	}
	// Anything the client pipelined after its handshake is sitting in the
	// hijack buffer; it belongs to the upgraded protocol and would be lost.
	if n := clientBuf.Reader.Buffered(); n > 0 {
		if pending, err := clientBuf.Reader.Peek(n); err == nil {
			upstream.Write(pending)
		}
	}

	if setter, ok := w.(statusSetter); ok {
		setter.SetStatus(http.StatusSwitchingProtocols)
	}
	logger.Debugf("Upgraded to %s via %s", proto, r.URL.Host)

	// An upgraded connection is a tunnel by every measure that matters here:
	// long-lived, carrying traffic a request counter cannot see, and gone from
	// the gauge only when it closes.
	obs.tunnelOpened()
	go transferPair(upstream, clientConn, obs.tunnelClosed)
}

func handleConnect(w http.ResponseWriter, r *http.Request, logger *log.Logger, pol Policy, dialer *net.Dialer, obs Observer) {
	logger.Debugf("CONNECT tunnel %s", r.Host)

	dial := pol.dialContext(dialer)
	if pol.chained(r.Host) {
		// The policy is checked here rather than in the dialer, because the
		// dialer is about to connect to the parent and would evaluate the rules
		// against the parent's address rather than the destination's.
		if err := pol.checkDestination(clientIP(r.RemoteAddr), r.Host); err != nil {
			logger.Warn("Refused CONNECT destination",
				log.String("host", r.Host), log.String("client", clientIP(r.RemoteAddr)),
				log.String("request_id", reqid.FromContext(r.Context())))
			obs.denied(deniedScope(err))
			http.Error(w, "Destination not permitted", http.StatusForbidden)
			return
		}
		dial = pol.dialThroughParent(dialer, logger)
	}

	// The same policy-aware dial the plain-HTTP path uses, so a tunnel cannot
	// reach anywhere an ordinary request could not.
	destConn, err := dial(r.Context(), "tcp", r.Host)
	if err != nil {
		if denied(err) {
			logger.Warn("Refused CONNECT destination",
				log.String("host", r.Host), log.String("client", clientIP(r.RemoteAddr)),
				log.String("request_id", reqid.FromContext(r.Context())))
			obs.denied(deniedScope(err))
			http.Error(w, "Destination not permitted", http.StatusForbidden)
			return
		}
		logger.Errorf("CONNECT dial error: %v", err)
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			http.Error(w, "Gateway timeout", http.StatusGatewayTimeout)
			return
		}
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	markServed(w)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		destConn.Close()
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Errorf("Hijack error: %v", err)
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		destConn.Close()
		return
	}
	_, err = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		destConn.Close()
		clientConn.Close()
		return
	}
	obs.tunnelOpened()
	go transferPair(destConn, clientConn, obs.tunnelClosed)
}

// dialThroughParent connects to the parent proxy and issues a nested CONNECT
// for the real destination, returning the tunnelled connection.
//
// The transport's Proxy hook cannot do this: CONNECT is served by hijacking and
// splicing sockets, so the handler dials for itself and has to speak the parent
// protocol directly. The parent's response is read and checked — a non-200 is a
// refusal by the parent, and splicing regardless would hand the client a tunnel
// that silently carries the parent's error page instead of the origin.
func (p Policy) dialThroughParent(d *net.Dialer, logger *log.Logger) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		parent := p.parent().Addr()
		conn, err := d.DialContext(ctx, network, parent)
		if err != nil {
			return nil, fmt.Errorf("dialling the upstream proxy %s: %w", parent, err)
		}

		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if auth := p.parent().AuthHeader(); auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
		}
		if err := req.Write(conn); err != nil {
			conn.Close()
			return nil, fmt.Errorf("sending CONNECT to the upstream proxy: %w", err)
		}

		// The buffered reader must not read past the response, or bytes the
		// tunnel owns would be swallowed here. A CONNECT response has no body,
		// so ReadResponse stops at the blank line.
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("reading the upstream proxy's CONNECT response: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("upstream proxy refused CONNECT to %s: %s", addr, resp.Status)
		}
		if n := br.Buffered(); n > 0 {
			// The parent sent tunnel bytes in the same read. Dropping them
			// would corrupt the very first thing the client sees, which for TLS
			// is the ServerHello.
			pending, _ := br.Peek(n)
			return &prefixedConn{Conn: conn, pending: pending}, nil
		}
		return conn, nil
	}
}

// prefixedConn replays bytes already read from the socket before reading more.
type prefixedConn struct {
	net.Conn
	pending []byte
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	io.Copy(dst, src)
	dst.Close()
	src.Close()
}

// transferPair splices two connections and runs done once, when the tunnel is
// finished. Both directions are pumped; whichever ends first closes both, so
// waiting for a single one is enough and a sync.Once is not needed.
func transferPair(a, b io.ReadWriteCloser, done func()) {
	go transfer(a, b)
	transfer(b, a)
	if done != nil {
		done()
	}
}

// hopByHopHeaders are meaningful only between one sender and the immediate
// recipient, and must not be forwarded across a proxy hop (RFC 7230 §6.1).
// Proxy-Authorization matters most here: it carries the credentials the client
// used on *us*, and forwarding it hands them to every origin the client visits.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHop deletes the per-hop headers, including any the peer named in
// its own Connection header, which is how a sender extends the list.
func removeHopByHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
