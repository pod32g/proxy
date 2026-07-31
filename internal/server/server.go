package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
	Logger    *log.Logger
	Clients   *ClientTracker
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

func (s *Server) newHTTPServer(addr string) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	if s.Clients != nil {
		srv.ConnState = s.Clients.ConnState
	}
	return srv
}

// Start launches the HTTP server and, if configured, an HTTPS server. It blocks
// until a listener fails or the process is asked to stop, then drains in-flight
// requests before returning.
func (s *Server) Start() error {
	if s.Handler == nil {
		s.Handler = http.DefaultServeMux
	}

	https := s.HTTPSAddr != ""
	if https {
		// Refuse to start rather than quietly serving plaintext only. Setting
		// -https and mistyping -cert used to produce a proxy that came up
		// clean, logged nothing about TLS, and served HTTP.
		if s.CertFile == "" || s.KeyFile == "" {
			return fmt.Errorf("-https %s requires both -cert and -key", s.HTTPSAddr)
		}
		// Load the keypair here so a bad certificate fails at startup instead
		// of on the first HTTPS request.
		if _, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile); err != nil {
			return fmt.Errorf("loading TLS keypair: %w", err)
		}
	}

	servers := []*http.Server{s.newHTTPServer(s.HTTPAddr)}
	if https {
		servers = append(servers, s.newHTTPServer(s.HTTPSAddr))
	}

	// Buffered so a failing listener never blocks on a send nobody reads.
	errCh := make(chan error, len(servers))

	if https {
		go func() {
			s.Logger.Info("Starting HTTPS proxy on", s.HTTPSAddr)
			if err := servers[1].ListenAndServeTLS(s.CertFile, s.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				// A dead TLS listener used to be logged and ignored, leaving a
				// process that answers /healthz on HTTP while the port people
				// actually connect to is gone.
				errCh <- fmt.Errorf("HTTPS server failed: %w", err)
			}
		}()
	}
	go func() {
		s.Logger.Info("Starting HTTP proxy on", s.HTTPAddr)
		if err := servers[0].ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	var runErr error
	select {
	case runErr = <-errCh:
	case sig := <-stop:
		s.Logger.Info("Received", sig.String()+", shutting down")
	}

	// Drain either way: even on a listener failure the other one may still be
	// serving requests worth finishing.
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			s.Logger.Error("Shutdown:", err)
		}
	}
	// Shutdown does not track hijacked connections, so an established CONNECT
	// tunnel is closed when the process exits rather than drained here.
	s.Logger.Info("Shutdown complete")
	return runErr
}
