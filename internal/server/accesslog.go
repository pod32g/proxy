package server

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	log "github.com/pod32g/simple-logger"
)

// AccessLogFormats lists the accepted access-log encodings.
//
//	off        — no access log
//	structured — one entry per request through the process logger, so it
//	             inherits -log-format and any log shipping already in place
//	combined   — NCSA combined log format, for tooling that already parses it
var AccessLogFormats = []string{"off", "structured", "combined"}

// ParseAccessLogFormat validates a format name. As with -log-level and
// -log-format, a typo is an error rather than a silent fallback: quietly
// disabling the access log is the failure nobody notices until they need it.
func ParseAccessLogFormat(format string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(format))
	for _, known := range AccessLogFormats {
		if f == known {
			return f, nil
		}
	}
	return "", fmt.Errorf("invalid access log format %q (want one of %s)",
		format, strings.Join(AccessLogFormats, ", "))
}

// NewAccessLog returns the Completed hook for a format, or nil when the access
// log is off. A nil hook is how "disabled" is expressed all the way down: the
// accounting middleware skips the record entirely rather than building one and
// throwing it away.
//
// logger is used by the structured format; out by the combined format. Either
// may be nil when the other is in use.
func NewAccessLog(format string, logger *log.Logger, out io.Writer) func(Exchange) {
	switch format {
	case "structured":
		if logger == nil {
			return nil
		}
		return func(e Exchange) { logStructured(logger, e) }
	case "combined":
		if out == nil {
			return nil
		}
		return func(e Exchange) { writeCombined(out, e) }
	default:
		return nil
	}
}

// logStructured emits one entry per request through the process logger.
//
// INFO, not Debug: a record of what the proxy brokered is not a debugging aid,
// and a level nobody runs in production is the same as no log at all. No header
// is ever included, so Proxy-Authorization cannot leak through here.
func logStructured(logger *log.Logger, e Exchange) {
	fields := []log.Field{
		log.String("client", e.Client),
		log.String("method", e.Method),
		log.String("host", e.Host),
		log.Int("status", e.Status),
		log.Int("bytes_in", int(e.BytesIn)),
		log.Int("bytes_out", int(e.BytesOut)),
		log.String("duration", e.Duration.Round(time.Microsecond).String()),
	}
	if e.Path != "" {
		fields = append(fields, log.String("path", e.Path))
	}
	if e.RequestID != "" {
		fields = append(fields, log.String("request_id", e.RequestID))
	}
	if e.Listener != "" {
		fields = append(fields, log.String("listener", e.Listener))
	}
	if e.Protocol != "" {
		fields = append(fields, log.String("upstream_proto", e.Protocol))
	}
	if e.Tunnel {
		fields = append(fields, log.Bool("tunnel", true))
	}
	logger.Info("access", fields...)
}

// writeCombined emits NCSA combined format, which existing tooling can consume
// unchanged.
//
// The identity and user fields are always "-": the proxy does record which
// credential was used, but writing a username into a log format whose readers
// treat it as low-sensitivity is a decision for PROXY-56's audit trail, not a
// side effect of turning on an access log.
func writeCombined(out io.Writer, e Exchange) {
	// The request line has no query string and no userinfo by construction —
	// see destination — so nothing needs redacting here.
	target := e.Host + e.Path
	line := strings.Builder{}
	line.WriteString(e.Client)
	line.WriteString(` - - [`)
	line.WriteString(time.Now().Format("02/Jan/2006:15:04:05 -0700"))
	line.WriteString(`] "`)
	line.WriteString(quoteField(e.Method))
	line.WriteByte(' ')
	line.WriteString(quoteField(target))
	line.WriteString(` HTTP/1.1" `)
	line.WriteString(strconv.Itoa(e.Status))
	line.WriteByte(' ')
	line.WriteString(strconv.FormatInt(e.BytesOut, 10))
	// Referer and User-Agent are the last two combined fields. They are client
	// -controlled strings that would have to be escaped and are not worth the
	// exposure, so they are recorded as absent rather than forwarded.
	line.WriteString(` "-" "-"` + "\n")
	io.WriteString(out, line.String())
}

// quoteField neutralises anything in a client-controlled string that could
// forge a field boundary or a new line in the output. A log format is a parser,
// and a request is attacker-controlled input to it.
func quoteField(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
