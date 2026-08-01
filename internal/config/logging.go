package config

import (
	"fmt"
	"io"
	"strings"

	log "github.com/pod32g/simple-logger"
)

// LogFormats lists the accepted output encodings.
//
//	text    — one human-readable line per entry, fields as key=value
//	json    — one JSON object per entry, for log aggregators
//	console — text with colour and alignment, for a terminal
var LogFormats = []string{"text", "json", "console"}

// ParseLogFormat validates a format name. Like the log level, an unrecognised
// value is an error rather than a silent fallback: a typo that quietly drops
// you back to text would be discovered by whatever downstream system stopped
// receiving parseable records.
func ParseLogFormat(format string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(format))
	for _, known := range LogFormats {
		if f == known {
			return f, nil
		}
	}
	return "", fmt.Errorf("invalid log format %q (want one of %s)", format, strings.Join(LogFormats, ", "))
}

// redactedFieldKeys are field names whose values are never safe to emit. The
// proxy does not log these today; the redactor is defence in depth, so that a
// future call site cannot leak one by adding a field.
var redactedFieldKeys = []string{
	"password", "passwd", "secret", "token", "credential", "credentials",
	"authorization", "proxy-authorization", "cookie", "set-cookie", "api-key", "apikey",
}

// NewLogger builds the process logger for the given format.
func NewLogger(out io.Writer, level log.LogLevel, format string) (*log.Logger, error) {
	opts := []log.Option{
		log.WithOutput(out),
		log.WithLevel(level),
		log.WithRedactor(log.NewKeyRedactor(redactedFieldKeys...)),
	}
	switch format {
	case "json":
		opts = append(opts, log.WithJSON())
	case "console":
		opts = append(opts, log.WithConsole())
	}
	return log.New(opts...)
}

// sensitiveHeaderMarkers match header names whose values must not be logged.
// A custom header is exactly where an operator puts an upstream API key, so
// "Set header name=X-Api-Key value=..." at INFO would write that credential to
// the log — and, with JSON output, ship it to wherever logs are shipped.
var sensitiveHeaderMarkers = []string{
	"authorization", "cookie", "token", "secret", "password",
	"api-key", "apikey", "credential", "session",
}

// RedactedValue is substituted for a header value that must not be logged.
const RedactedValue = "[redacted]"

// RedactHeaderValue returns the value to log for a header, replacing it when
// the header's name suggests it carries a credential.
func RedactHeaderValue(name, value string) string {
	lower := strings.ToLower(name)
	for _, marker := range sensitiveHeaderMarkers {
		if strings.Contains(lower, marker) {
			return RedactedValue
		}
	}
	return value
}
