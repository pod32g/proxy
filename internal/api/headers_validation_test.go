package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PROXY-89. The rule parser refuses a header value containing CR, LF or NUL;
// the headers map — the same headers, set a different way — validated nothing
// and answered 204. Nothing reached the wire, because Go's transport refuses to
// send such a value, but every request through that listener then failed with a
// 502 whose cause was in a log line somewhere else.
func TestInvalidHeadersAreRefusedAtTheWrite(t *testing.T) {
	cfg, h := newAPI()
	for _, tc := range []struct{ name, body string }{
		{"CRLF in value", `{"name":"X-A","value":"b\r\nX-Injected: 1"}`},
		{"LF in value", `{"name":"X-A","value":"b\nX-Injected: 1"}`},
		{"NUL in value", `{"name":"X-A","value":"b\u0000c"}`},
		{"colon in name", `{"name":"X-C: evil","value":"1"}`},
		{"space in name", `{"name":"X D","value":"1"}`},
		{"empty name is not a header", `{"name":" ","value":"1"}`},
		{"hop-by-hop", `{"name":"Proxy-Authorization","value":"Basic x"}`},
		{"per-client too", `{"client":"10.0.0.1","name":"X-A","value":"b\r\nX: 1"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/headers", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("answered %d, want 400", rec.Code)
			}
		})
	}
	if got := cfg.GetHeaders(); len(got) != 0 {
		t.Errorf("a rejected header was stored anyway: %v", got)
	}
	if got := cfg.GetAllClientHeaders(); len(got) != 0 {
		t.Errorf("a rejected client header was stored anyway: %v", got)
	}

	// And a good one still works, so this is a filter and not a wall.
	req := httptest.NewRequest("POST", "/headers", strings.NewReader(`{"name":"X-Ok","value":"1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("a valid header answered %d", rec.Code)
	}
	if cfg.GetHeaders()["X-Ok"] != "1" {
		t.Errorf("a valid header was not stored: %v", cfg.GetHeaders())
	}
}
