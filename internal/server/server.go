package server

import (
	"crypto/tls"
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

// Start launches the HTTP server and, if configured, an HTTPS server.
func (s *Server) Start() error {
	if s.Handler == nil {
		s.Handler = http.DefaultServeMux
	}

	if s.HTTPSAddr != "" && s.CertFile != "" && s.KeyFile != "" {
		go func() {
			httpsSrv := &http.Server{
				Addr:         s.HTTPSAddr,
				Handler:      s.Handler,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  30 * time.Second,
				TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
				TLSConfig:    &tls.Config{NextProtos: []string{"http/1.1"}},
			}
			if s.Clients != nil {
				httpsSrv.ConnState = s.Clients.ConnState
			}
			s.Logger.Info("Starting HTTPS proxy on", s.HTTPSAddr)
			if err := httpsSrv.ListenAndServeTLS(s.CertFile, s.KeyFile); err != nil && err != http.ErrServerClosed {
				s.Logger.Error("HTTPS server failed: %v", err)
			}
		}()
	}

	httpSrv := &http.Server{
		Addr:         s.HTTPAddr,
		Handler:      s.Handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	if s.Clients != nil {
		httpSrv.ConnState = s.Clients.ConnState
	}
	s.Logger.Info("Starting HTTP proxy on", s.HTTPAddr)
	return httpSrv.ListenAndServe()
}
