package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseBytes reads a size written the way an operator writes one: 256MB, 32MiB,
// or a plain byte count.
//
// Exported and shared because LoadFile and main both need it. Left in main, the
// config file would accept a size the process then rejected at startup — one
// more setting where the file says one thing and the proxy does another, which
// is the failure this project keeps finding.
//
// Both spellings are supported because both are in common use, and guessing
// which one was meant is how you end up off by 5%.
func ParseBytes(s string) (int64, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	for _, sfx := range []struct {
		suffix string
		mult   int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
		{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9},
		{"K", 1e3}, {"M", 1e6}, {"G", 1e9},
	} {
		digits, ok := strings.CutSuffix(upper, sfx.suffix)
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(digits), 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%q is not a positive size", s)
		}
		return n * sfx.mult, nil
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q is not a size (try 256MB)", s)
	}
	return n, nil
}
