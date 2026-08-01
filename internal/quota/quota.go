// Package quota bounds how much a client may push through the proxy.
//
// Two kinds of allowance are enforced, and they are not the same kind of
// control:
//
// A request quota is admission control. The cost of a request is known before
// it runs, so an over-quota request is refused cleanly with 429 and nothing is
// wasted.
//
// A byte quota cannot work that way. For a streaming response the total is only
// known once it has been delivered, and enforcing a ceiling mid-transfer would
// hand the client a truncated body that looks like a complete one. So bytes are
// charged after the fact: traffic is metered as it flows, the bucket is allowed
// to go into deficit, and the next request from that client is refused until it
// refills. The deficit is floored at one full burst, so a single large transfer
// costs at most one refill window rather than locking a client out for hours.
package quota

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

// Limit is a token-bucket allowance: how fast the bucket refills, and how much
// it can hold. The zero value is unlimited.
type Limit struct {
	// PerSecond is the refill rate. Zero or negative means unlimited.
	PerSecond float64
	// Burst is the bucket capacity. Zero means one second's worth.
	Burst float64

	// text is the limit as the operator wrote it, so a rule set round-trips to
	// the store and the UI unchanged rather than coming back as "10485760/s".
	text string
}

// Unlimited reports whether the limit constrains anything.
func (l Limit) Unlimited() bool { return l.PerSecond <= 0 }

// capacity is the bucket size, defaulting to one second of refill.
func (l Limit) capacity() float64 {
	if l.Burst > 0 {
		return l.Burst
	}
	return l.PerSecond
}

// String renders the limit as written.
func (l Limit) String() string {
	if l.text != "" {
		return l.text
	}
	if l.Unlimited() {
		return "unlimited"
	}
	return fmt.Sprintf("%g/s", l.PerSecond)
}

// Spec is the pair of allowances that apply to one scope.
type Spec struct {
	Requests Limit
	Bytes    Limit
}

// Empty reports whether the spec constrains anything.
func (s Spec) Empty() bool { return s.Requests.Unlimited() && s.Bytes.Unlimited() }

// merge fills unset fields from a fallback. An override that names only a
// request rate keeps the default byte rate rather than silently becoming
// unlimited, which is the reading an operator expects from "override".
func (s Spec) merge(base Spec) Spec {
	if s.Requests.PerSecond == 0 && s.Requests.text == "" {
		s.Requests = base.Requests
	}
	if s.Bytes.PerSecond == 0 && s.Bytes.text == "" {
		s.Bytes = base.Bytes
	}
	return s
}

// ClientLimit is a per-client override, keyed by address or prefix.
type ClientLimit struct {
	// Value as written, for round-tripping and error messages.
	Value string
	Spec  Spec

	net *net.IPNet
}

// ones returns the prefix length, used to rank specificity.
func (c ClientLimit) ones() int {
	if c.net == nil {
		return -1
	}
	n, _ := c.net.Mask.Size()
	return n
}

// Set is a parsed quota configuration.
type Set struct {
	// Global is the ceiling across every client at once.
	Global Spec
	// ClientDefault applies to each client separately.
	ClientDefault Spec
	// Clients are per-client overrides; the longest matching prefix wins, as in
	// the client access table.
	Clients []ClientLimit
}

// Empty reports whether the set constrains anything.
func (s *Set) Empty() bool {
	return s == nil || (s.Global.Empty() && s.ClientDefault.Empty() && len(s.Clients) == 0)
}

// For returns the allowance in force for a client: its own override merged over
// the per-client default, or the default alone.
func (s *Set) For(clientIP string) Spec {
	if s == nil {
		return Spec{}
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return s.ClientDefault
	}
	var best *ClientLimit
	for i := range s.Clients {
		c := &s.Clients[i]
		if c.net == nil || !c.net.Contains(ip) {
			continue
		}
		if best == nil || c.ones() > best.ones() {
			best = c
		}
	}
	if best == nil {
		return s.ClientDefault
	}
	return best.Spec.merge(s.ClientDefault)
}

// Parse reads a quota rule per line. Blank lines and # comments are ignored.
//
//	global requests 500/s burst 1000
//	global bytes 100MB/s
//	client requests 50/s burst 100
//	client bytes 10MB/s
//	client 10.0.0.0/8 requests 200/s burst 400
//	client 10.1.2.3 bytes unlimited
//
// "global" is the ceiling across all clients at once; a bare "client" line is
// the per-client default; a "client <address-or-cidr>" line overrides it for
// that range, longest prefix wins.
func Parse(text string) (*Set, error) {
	set := &Set{}
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if err := set.parseLine(trimmed); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return set, nil
}

func (s *Set) parseLine(line string) error {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return fmt.Errorf("rule %q: want \"global <requests|bytes> <rate>\" or \"client [address] <requests|bytes> <rate>\"", line)
	}

	switch strings.ToLower(fields[0]) {
	case "global":
		kind, limit, err := parseKindAndLimit(line, fields[1:])
		if err != nil {
			return err
		}
		s.Global.set(kind, limit)
		return nil
	case "client":
		// "client requests 50/s" sets the default; "client 10.0.0.0/8 requests
		// 50/s" overrides one range. The second word tells them apart.
		if isKind(fields[1]) {
			kind, limit, err := parseKindAndLimit(line, fields[1:])
			if err != nil {
				return err
			}
			s.ClientDefault.set(kind, limit)
			return nil
		}
		if len(fields) < 4 {
			return fmt.Errorf("rule %q: want \"client <address-or-cidr> <requests|bytes> <rate>\"", line)
		}
		network, err := parseCIDR(fields[1])
		if err != nil {
			return fmt.Errorf("rule %q: %v", line, err)
		}
		kind, limit, err := parseKindAndLimit(line, fields[2:])
		if err != nil {
			return err
		}
		// Repeated lines for the same range accumulate rather than replacing, so
		// requests and bytes can be given on separate lines.
		for i := range s.Clients {
			if s.Clients[i].Value == fields[1] {
				s.Clients[i].Spec.set(kind, limit)
				return nil
			}
		}
		entry := ClientLimit{Value: fields[1], net: network}
		entry.Spec.set(kind, limit)
		s.Clients = append(s.Clients, entry)
		return nil
	default:
		return fmt.Errorf("rule %q: first word must be global or client", line)
	}
}

func (s *Spec) set(kind string, limit Limit) {
	if kind == "bytes" {
		s.Bytes = limit
		return
	}
	s.Requests = limit
}

func isKind(field string) bool {
	switch strings.ToLower(field) {
	case "requests", "bytes":
		return true
	}
	return false
}

// parseCIDR accepts a bare address as a single-host entry; requiring /32 is a
// papercut with no upside.
func parseCIDR(value string) (*net.IPNet, error) {
	cidr := value
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an address or prefix", value)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		cidr = fmt.Sprintf("%s/%d", cidr, bits)
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return network, nil
}

// parseKindAndLimit reads "<requests|bytes> <rate> [burst <n>]".
func parseKindAndLimit(line string, fields []string) (string, Limit, error) {
	kind := strings.ToLower(fields[0])
	if !isKind(kind) {
		return "", Limit{}, fmt.Errorf("rule %q: unknown quota %q (want requests or bytes)", line, fields[0])
	}
	if len(fields) < 2 {
		return "", Limit{}, fmt.Errorf("rule %q: %s needs a rate", line, kind)
	}

	rest := fields[1:]
	if strings.EqualFold(rest[0], "unlimited") || strings.EqualFold(rest[0], "none") {
		if len(rest) != 1 {
			return "", Limit{}, fmt.Errorf("rule %q: %q takes no burst", line, rest[0])
		}
		return kind, Limit{text: strings.ToLower(rest[0])}, nil
	}

	perSecond, err := parseRate(kind, rest[0])
	if err != nil {
		return "", Limit{}, fmt.Errorf("rule %q: %v", line, err)
	}
	limit := Limit{PerSecond: perSecond, text: strings.Join(rest, " ")}

	switch len(rest) {
	case 1:
	case 3:
		if !strings.EqualFold(rest[1], "burst") {
			return "", Limit{}, fmt.Errorf("rule %q: expected \"burst\", got %q", line, rest[1])
		}
		burst, err := parseAmount(kind, rest[2])
		if err != nil {
			return "", Limit{}, fmt.Errorf("rule %q: burst: %v", line, err)
		}
		if burst <= 0 {
			return "", Limit{}, fmt.Errorf("rule %q: burst must be positive", line)
		}
		// A burst below the per-second rate is almost always a typo, and it
		// quietly caps throughput at the burst rather than the rate.
		if burst < perSecond {
			return "", Limit{}, fmt.Errorf("rule %q: burst %s is smaller than the rate; it would cap throughput below the rate", line, rest[2])
		}
		limit.Burst = burst
	default:
		return "", Limit{}, fmt.Errorf("rule %q: want \"<rate>\" or \"<rate> burst <n>\"", line)
	}
	return kind, limit, nil
}

// parseRate reads "<amount>/<s|m|h>" and returns the amount per second.
func parseRate(kind, s string) (float64, error) {
	amountStr, unit, found := strings.Cut(s, "/")
	if !found {
		return 0, fmt.Errorf("rate %q must be written <amount>/<s|m|h>", s)
	}
	amount, err := parseAmount(kind, amountStr)
	if err != nil {
		return 0, err
	}
	if amount <= 0 {
		return 0, fmt.Errorf("rate %q must be positive (use \"unlimited\" for no limit)", s)
	}
	var per float64
	switch strings.ToLower(unit) {
	case "s", "sec", "second":
		per = 1
	case "m", "min", "minute":
		per = 60
	case "h", "hr", "hour":
		per = 3600
	default:
		return 0, fmt.Errorf("rate %q: unknown unit %q (want s, m or h)", s, unit)
	}
	return amount / per, nil
}

// sizeSuffixes are accepted on byte amounts. Both spellings are supported
// because both are in common use and guessing which one an operator meant is
// how you end up off by 5%.
var sizeSuffixes = []struct {
	suffix string
	mult   float64
}{
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40},
	{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12},
	{"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12},
}

// parseAmount reads a count, allowing size suffixes for byte quotas only. A
// request count in "MB" is a mistake worth reporting rather than accepting.
func parseAmount(kind, s string) (float64, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	for _, sfx := range sizeSuffixes {
		digits, ok := strings.CutSuffix(upper, sfx.suffix)
		if !ok {
			continue
		}
		if kind != "bytes" {
			return 0, fmt.Errorf("%q: size suffixes apply to byte quotas, not request counts", s)
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(digits), 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a number", s)
		}
		return n * sfx.mult, nil
	}
	n, err := strconv.ParseFloat(upper, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	if math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, fmt.Errorf("%q is not a finite number", s)
	}
	return n, nil
}

// String renders the set back to the syntax Parse accepts.
func (s *Set) String() string {
	if s == nil {
		return ""
	}
	var lines []string
	add := func(prefix string, spec Spec) {
		if !spec.Requests.Unlimited() || spec.Requests.text != "" {
			lines = append(lines, prefix+"requests "+spec.Requests.String())
		}
		if !spec.Bytes.Unlimited() || spec.Bytes.text != "" {
			lines = append(lines, prefix+"bytes "+spec.Bytes.String())
		}
	}
	add("global ", s.Global)
	add("client ", s.ClientDefault)
	for _, c := range s.Clients {
		add("client "+c.Value+" ", c.Spec)
	}
	return strings.Join(lines, "\n")
}
