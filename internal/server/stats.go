package server

import (
	"sort"
	"strings"
	"sync"
)

// DomainStats tracks the number of requests per host.
type DomainStats struct {
	mu     sync.Mutex
	counts map[string]int
}

// NewDomainStats creates a new DomainStats instance.
func NewDomainStats() *DomainStats {
	return &DomainStats{counts: make(map[string]int)}
}

// Record increments the counter for the given host.
func (d *DomainStats) Record(host string) {
	if host == "" {
		return
	}
	host = strings.ToLower(host)
	d.mu.Lock()
	d.counts[host]++
	d.mu.Unlock()
}

// Stat represents a host and count pair.
type Stat struct {
	Host  string
	Count int
}

// Top returns the top n hosts sorted by request count.
func (d *DomainStats) Top(n int) []Stat {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Stat, 0, len(d.counts))
	for h, c := range d.counts {
		out = append(out, Stat{Host: h, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
