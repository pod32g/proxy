package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pod32g/proxy/internal/policy"
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
// reporting it as an upstream fault.
type errDenied struct{ reason string }

func (e *errDenied) Error() string { return e.reason }

func denied(err error) bool {
	var d *errDenied
	return errors.As(err, &d)
}

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
					return &errDenied{fmt.Sprintf("destination %s is not permitted by policy (%s)", requested, rule)}
				}
				// An explicit allow overrides the private-address default:
				// naming an internal range in the rules is a deliberate act.
				return nil
			}
			if p.blockedIP(ip) {
				return &errDenied{fmt.Sprintf("destination %s is not permitted (use -allow-private to allow it)", ip)}
			}
			return nil
		},
	}
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
			return nil, &errDenied{fmt.Sprintf("destination %s is not permitted by policy (%s)", host, rule)}
		}
		return d.DialContext(context.WithValue(ctx, hostKey{}, host), network, addr)
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
func NewForward(logger *log.Logger, headers func(string) map[string]string, pol Policy) http.Handler {
	dialer := pol.dialer()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = pol.dialContext(dialer)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			logger.Debugf("CONNECT request %s", r.Host)
			if err := pol.connectAllowed(r.Host); err != nil {
				logger.Warnf("Refused CONNECT: %v", err)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			handleConnect(w, withClient(r), logger, pol, dialer)
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
			handleUpgrade(w, r, transport, headers, logger, proto)
			return
		}
		outReq := r.Clone(context.WithValue(r.Context(), clientKey{}, clientIP(r.RemoteAddr)))
		outReq.RequestURI = ""
		// r.Clone copies every header the client sent to the *proxy*, including
		// the credentials it used to authenticate to us. Strip the per-hop set
		// before it reaches the origin.
		removeHopByHop(outReq.Header)
		for k, v := range headers(clientIP(r.RemoteAddr)) {
			outReq.Header.Set(k, v)
		}
		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			// A policy rejection is the client asking for somewhere it is not
			// allowed to go. That is a refusal, not an upstream fault, and
			// logging it at ERROR would put routine enforcement in with real
			// failures.
			if denied(err) {
				logger.Warn("Refused destination",
					log.String("host", r.URL.Host), log.String("client", clientIP(r.RemoteAddr)))
				http.Error(w, "Destination not permitted", http.StatusForbidden)
				return
			}
			logger.Errorf("Upstream error: %v", err)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		removeHopByHop(resp.Header)
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
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
	headers func(string) map[string]string, logger *log.Logger, proto string,
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

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		if denied(err) {
			logger.Warn("Refused upgrade destination", log.String("host", r.URL.Host))
			http.Error(w, "Destination not permitted", http.StatusForbidden)
			return
		}
		logger.Errorf("Upgrade upstream error: %v", err)
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}

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

	go transfer(upstream, clientConn)
	go transfer(clientConn, upstream)
}

func handleConnect(w http.ResponseWriter, r *http.Request, logger *log.Logger, pol Policy, dialer *net.Dialer) {
	logger.Debugf("CONNECT tunnel %s", r.Host)
	// The same policy-aware dial the plain-HTTP path uses, so a tunnel cannot
	// reach anywhere an ordinary request could not.
	destConn, err := pol.dialContext(dialer)(r.Context(), "tcp", r.Host)
	if err != nil {
		if denied(err) {
			logger.Warn("Refused CONNECT destination",
				log.String("host", r.Host), log.String("client", clientIP(r.RemoteAddr)))
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
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	io.Copy(dst, src)
	dst.Close()
	src.Close()
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
