package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandlerServesFiles(t *testing.T) {
	h := newHandler("../../web")
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
