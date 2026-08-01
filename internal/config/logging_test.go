package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	log "github.com/pod32g/simple-logger"
)

func TestParseLogFormat(t *testing.T) {
	for _, in := range []string{"text", "json", "console", "JSON", " json "} {
		if _, err := ParseLogFormat(in); err != nil {
			t.Errorf("ParseLogFormat(%q) = %v, want ok", in, err)
		}
	}
	for _, in := range []string{"", "yaml", "jsonl", "structured"} {
		if _, err := ParseLogFormat(in); err == nil {
			t.Errorf("ParseLogFormat(%q) accepted an unknown format", in)
		}
	}
	// The error should name the offending value and the alternatives, since it
	// is the only feedback an operator gets before the process exits.
	_, err := ParseLogFormat("yaml")
	if !strings.Contains(err.Error(), "yaml") || !strings.Contains(err.Error(), "json") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// Asserted on parsed records rather than substrings: a substring match would
// pass on output that is not actually valid JSON, which is the one thing a log
// aggregator cannot tolerate.
func TestJSONFormatEmitsParseableRecords(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewLogger(&buf, log.INFO, "json")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("Starting HTTP proxy", log.String("addr", "127.0.0.1:8080"))
	logger.Warn("Rejected credentials", log.String("source", "203.0.113.9"), log.Int("failures_in_window", 3))
	logger.Infof("CONNECT allowed to ports %s", "443")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(lines), buf.String())
	}

	var first map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v (%q)", err, lines[0])
	}
	for _, key := range []string{"timestamp", "level", "message"} {
		if _, ok := first[key]; !ok {
			t.Errorf("record is missing the %q key: %v", key, first)
		}
	}
	if first["level"] != "INFO" || first["message"] != "Starting HTTP proxy" {
		t.Errorf("unexpected record: %v", first)
	}
	// Fields are promoted to top-level keys, which is what makes them filterable.
	if first["addr"] != "127.0.0.1:8080" {
		t.Errorf("field not present as a top-level key: %v", first)
	}

	var second map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v", err)
	}
	if second["source"] != "203.0.113.9" {
		t.Errorf("string field missing: %v", second)
	}
	if n, ok := second["failures_in_window"].(float64); !ok || n != 3 {
		t.Errorf("numeric field should stay a JSON number, got %#v", second["failures_in_window"])
	}

	// A formatted message must survive as a single message value, not leak the
	// verb or split across keys.
	var third map[string]interface{}
	if err := json.Unmarshal([]byte(lines[2]), &third); err != nil {
		t.Fatalf("line 3 is not valid JSON: %v", err)
	}
	if third["message"] != "CONNECT allowed to ports 443" {
		t.Errorf("formatted message mangled: %#v", third["message"])
	}
}

// Text remains the default and must not accidentally become JSON.
func TestTextFormatIsNotJSON(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewLogger(&buf, log.INFO, "text")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("Starting HTTP proxy", log.String("addr", ":8080"))

	line := strings.TrimSpace(buf.String())
	var any map[string]interface{}
	if json.Unmarshal([]byte(line), &any) == nil {
		t.Errorf("text format produced JSON: %q", line)
	}
	if !strings.Contains(line, "addr=:8080") {
		t.Errorf("text format lost the field: %q", line)
	}
}

// The redactor is defence in depth: no current call site logs these keys, and a
// future one must not be able to leak a credential by adding a field.
func TestRedactorHidesSensitiveFieldValues(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewLogger(&buf, log.INFO, "json")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hypothetical future call site",
		log.String("password", "hunter2"),
		log.String("token", "abc123"),
		log.String("addr", ":8080"))

	if strings.Contains(buf.String(), "hunter2") || strings.Contains(buf.String(), "abc123") {
		t.Fatalf("secret survived redaction: %s", buf.String())
	}
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["addr"] != ":8080" {
		t.Errorf("redaction removed an innocent field: %v", rec)
	}
}

// A custom header is exactly where an operator puts an upstream API key, so the
// value must not reach the log when the name says it is a credential.
func TestRedactHeaderValue(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"X-Api-Key", "secret", RedactedValue},
		{"Authorization", "Bearer abc", RedactedValue},
		{"authorization", "Bearer abc", RedactedValue},
		{"Cookie", "sid=1", RedactedValue},
		{"X-Session-Token", "t", RedactedValue},
		{"X-Auth-Password", "p", RedactedValue},
		{"X-Team", "blue", "blue"},
		{"X-Proxy-Name", "edge", "edge"},
		{"Accept", "application/json", "application/json"},
	} {
		if got := RedactHeaderValue(tc.name, tc.value); got != tc.want {
			t.Errorf("RedactHeaderValue(%q, %q) = %q, want %q", tc.name, tc.value, got, tc.want)
		}
	}
}
