package server

import (
	"net/http"
	"testing"
)

// A proxy cannot bound how long a transfer takes: WriteTimeout severed long
// downloads and the UI's own SSE streams, and ReadTimeout capped uploads.
func TestServerHasNoWholeRequestTimeouts(t *testing.T) {
	s := &Server{Handler: http.NotFoundHandler(), Clients: NewClientTracker()}
	srv := s.newHTTPServer(":0")

	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout must stay unset, got %v", srv.WriteTimeout)
	}
	if srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout must stay unset, got %v", srv.ReadTimeout)
	}
	if srv.ReadHeaderTimeout != readHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, readHeaderTimeout)
	}
	if srv.IdleTimeout != idleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, idleTimeout)
	}
	if srv.ConnState == nil {
		t.Error("connection tracking not wired up")
	}
}
