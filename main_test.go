package main

import "testing"

func TestGetenv(t *testing.T) {
    key := "TEST_ENV_VAR"
    if got := getenv(key, "default"); got != "default" {
        t.Fatalf("expected default, got %s", got)
    }
    t.Setenv(key, "value")
    if got := getenv(key, "default"); got != "value" {
        t.Fatalf("expected value, got %s", got)
    }
}

func TestHeaderFlags(t *testing.T) {
    var h headerFlags
    if err := h.Set("A=1"); err != nil {
        t.Fatalf("Set returned error: %v", err)
    }
    if h.String() != "A=1" {
        t.Fatalf("unexpected string: %s", h.String())
    }
    if err := h.Set("badformat"); err == nil {
        t.Fatalf("expected error for bad format")
    }
}
