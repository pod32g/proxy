package server

import (
	"net/http"
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

// Start launches the HTTP server and, if configured, an HTTPS server.
func (s *Server) Start() error {
	if s.Handler == nil {
		s.Handler = http.DefaultServeMux
	}

	if s.HTTPSAddr != "" && s.CertFile != "" && s.KeyFile != "" {
		go func() {
			httpsSrv := s.newHTTPServer(s.HTTPSAddr)
			s.Logger.Info("Starting HTTPS proxy on", s.HTTPSAddr)
			if err := httpsSrv.ListenAndServeTLS(s.CertFile, s.KeyFile); err != nil && err != http.ErrServerClosed {
				s.Logger.Error("HTTPS server failed: %v", err)
			}
		}()
	}

	httpSrv := s.newHTTPServer(s.HTTPAddr)
	s.Logger.Info("Starting HTTP proxy on", s.HTTPAddr)
	return httpSrv.ListenAndServe()
}
