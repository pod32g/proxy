package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouterAuth(t *testing.T) {
	r := &Router{
		Proxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		AuthEnabled: true,
		Username:    "user",
		Password:    "pass",
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Result().StatusCode)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.SetBasicAuth("user", "pass")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Result().StatusCode)
	}

	cred := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("Proxy-Authorization", "Basic "+cred)
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec3.Result().StatusCode)
	}
}

func TestRouterAuthDisabled(t *testing.T) {
	r := &Router{
		Proxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		AuthEnabled: false,
		Username:    "user",
		Password:    "pass",
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Result().StatusCode)
	}
}
