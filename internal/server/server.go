package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/pod32g/simple-logger"
)

// Server contains configuration for running the proxy over HTTP and HTTPS.
type Server struct {
	HTTPAddr  string
	HTTPSAddr string
	CertFile  string
	KeyFile   string
	Handler   http.Handler

	// AdminAddr, when set, serves AdminHandler on its own listener. The point
	// is a boundary: the admin surface can then be bound to a management
	// interface and firewalled independently of the port clients proxy through.
	AdminAddr     string
	AdminCertFile string
	AdminKeyFile  string
	AdminHandler  http.Handler

	// Extra are additional listeners beyond the flag-configured ones, each with
	// its own handler and TLS material. The single-listener flags above remain
	// exactly what they were and become the listener named "http" (and "https").
	Extra []Listener

	Logger  *log.Logger
	Clients *ClientTracker
}

// Listener is one additional bound address and what it serves.
type Listener struct {
	Name     string
	Addr     string
	Handler  http.Handler
	CertFile string
	KeyFile  string
}

// A proxy must not bound how long a transfer takes: it has no idea whether the
// body is a 200-byte JSON reply, a multi-gigabyte download, or an SSE stream
// that stays open for hours. ReadTimeout and WriteTimeout cover the whole
// request and response, so any value large enough for the slowest legitimate
// transfer is useless as a defence anyway. Bound the parts that should be
// bounded instead — how long a client may dawdle over its headers, and how long
// an idle keep-alive connection may sit — and let the bodies take as long as
// they take.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second

	// How long in-flight requests get to finish after a shutdown signal.
	shutdownGrace = 30 * time.Second
)

// listener is one bound address and what it serves.
type listener struct {
	name     string
	addr     string
	handler  http.Handler
	certFile string
	keyFile  string
	// track says whether connections here count towards the client gauge.
	// Admin traffic is an operator with a browser open, not a proxy client, and
	// counting it would quietly inflate the number the UI reports.
	track bool
}

func (l listener) tls() bool { return l.certFile != "" && l.keyFile != "" }

func (s *Server) newHTTPServer(l listener) *http.Server {
	srv := &http.Server{
		Addr:              l.addr,
		Handler:           l.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	if s.Clients != nil && l.track {
		srv.ConnState = s.Clients.ConnState
	}
	return srv
}

// listeners resolves the configuration into the set of servers to run,
// rejecting combinations that cannot work rather than starting a subset.
func (s *Server) listeners() ([]listener, error) {
	out := []listener{{name: "http", addr: s.HTTPAddr, handler: s.Handler, track: true}}

	if s.HTTPSAddr != "" {
		// Refuse to start rather than quietly serving plaintext only. Setting
		// -https and mistyping -cert used to produce a proxy that came up
		// clean, logged nothing about TLS, and served HTTP.
		if s.CertFile == "" || s.KeyFile == "" {
			return nil, fmt.Errorf("-https %s requires both -cert and -key", s.HTTPSAddr)
		}
		out = append(out, listener{
			name: "https", addr: s.HTTPSAddr, handler: s.Handler,
			certFile: s.CertFile, keyFile: s.KeyFile, track: true,
		})
	}

	for _, e := range s.Extra {
		if e.Name == "" || e.Addr == "" {
			return nil, fmt.Errorf("every listener needs a name and an address")
		}
		if e.Handler == nil {
			return nil, fmt.Errorf("listener %q has no handler", e.Name)
		}
		// Same all-or-nothing rule as everywhere else: half-configured TLS
		// would serve in the clear on a port the operator believes is secured.
		if (e.CertFile == "") != (e.KeyFile == "") {
			return nil, fmt.Errorf("listener %q: cert and key must be given together", e.Name)
		}
		out = append(out, listener{
			name: e.Name, addr: e.Addr, handler: e.Handler,
			certFile: e.CertFile, keyFile: e.KeyFile, track: true,
		})
	}

	if s.AdminAddr != "" {
		if s.AdminHandler == nil {
			return nil, fmt.Errorf("-admin-http %s requires an admin handler", s.AdminAddr)
		}
		// Same all-or-nothing rule as the proxy listener: half-configured TLS
		// on the admin port would serve the configuration UI in the clear.
		if (s.AdminCertFile == "") != (s.AdminKeyFile == "") {
			return nil, fmt.Errorf("-admin-cert and -admin-key must be given together")
		}
		out = append(out, listener{
			name: "admin", addr: s.AdminAddr, handler: s.AdminHandler,
			certFile: s.AdminCertFile, keyFile: s.AdminKeyFile,
		})
	}

	// Load every keypair up front so a bad certificate fails at startup rather
	// than on the first request to reach it.
	seen := make(map[string]string, len(out))
	for _, l := range out {
		if l.tls() {
			if _, err := tls.LoadX509KeyPair(l.certFile, l.keyFile); err != nil {
				return nil, fmt.Errorf("loading TLS keypair for the %s listener: %w", l.name, err)
			}
		}
		// Two listeners on one address is not a configuration anyone means. One
		// of them would win the bind and the other's rules would silently never
		// apply — the worst kind of misconfiguration, because it looks like it
		// worked.
		if prev, dup := seen[l.addr]; dup {
			return nil, fmt.Errorf("listeners %q and %q both bind %s", prev, l.name, l.addr)
		}
		seen[l.addr] = l.name
	}
	return out, nil
}

// bind opens every listening socket before anything starts serving.
//
// Binding inside the serving goroutines, as this used to, means a listener
// whose port is taken fails only after the others have been accepting traffic
// for however long it took to find out — a process that served real requests
// under a configuration the operator never got. Binding first makes a failure
// here a startup error that served nothing, and closes the sockets already
// opened rather than leaking them.
func bind(specs []listener) ([]net.Listener, error) {
	out := make([]net.Listener, 0, len(specs))
	for _, spec := range specs {
		ln, err := net.Listen("tcp", spec.addr)
		if err != nil {
			for _, open := range out {
				open.Close()
			}
			return nil, fmt.Errorf("binding the %s listener on %s: %w", spec.name, spec.addr, err)
		}
		out = append(out, ln)
	}
	return out, nil
}

// Start launches every configured listener. It blocks until one fails or the
// process is asked to stop, then drains in-flight requests before returning.
func (s *Server) Start() error {
	if s.Handler == nil {
		s.Handler = http.DefaultServeMux
	}

	specs, err := s.listeners()
	if err != nil {
		return err
	}

	// Every socket is bound before any of them starts serving, so a bind
	// failure is a startup error rather than a partial start.
	sockets, err := bind(specs)
	if err != nil {
		return err
	}

	servers := make([]*http.Server, len(specs))
	// Buffered so a failing listener never blocks on a send nobody reads.
	errCh := make(chan error, len(specs))

	for i, spec := range specs {
		srv := s.newHTTPServer(spec)
		servers[i] = srv
		go func(spec listener, srv *http.Server, sock net.Listener) {
			scheme := "HTTP"
			if spec.tls() {
				scheme = "HTTPS"
			}
			s.Logger.Info("Listening",
				log.String("listener", spec.name),
				log.String("scheme", scheme),
				log.String("addr", sock.Addr().String()))

			var err error
			if spec.tls() {
				err = srv.ServeTLS(sock, spec.certFile, spec.keyFile)
			} else {
				err = srv.Serve(sock)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				// A dead listener used to be logged and ignored, leaving a
				// process that answers /healthz while the port people actually
				// connect to is gone.
				errCh <- fmt.Errorf("%s listener failed: %w", spec.name, err)
			}
		}(spec, srv, sockets[i])
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	var runErr error
	select {
	case runErr = <-errCh:
	case sig := <-stop:
		s.Logger.Info("Shutting down", log.String("signal", sig.String()))
	}

	// Drain either way: even on a listener failure the others may still be
	// serving requests worth finishing.
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			s.Logger.Errorf("Shutdown: %v", err)
		}
	}
	// Shutdown does not track hijacked connections, so an established CONNECT
	// tunnel is closed when the process exits rather than drained here.
	s.Logger.Info("Shutdown complete")
	return runErr
}
