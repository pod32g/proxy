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
	subs   map[chan []Stat]struct{}
}

// NewDomainStats creates a new DomainStats instance.
func NewDomainStats() *DomainStats {
	return &DomainStats{counts: make(map[string]int), subs: make(map[chan []Stat]struct{})}
}

// Subscribe returns a channel that receives the top stats when they change.
func (d *DomainStats) Subscribe() chan []Stat {
	ch := make(chan []Stat, 1)
	d.mu.Lock()
	d.subs[ch] = struct{}{}
	ch <- d.topLocked(10)
	d.mu.Unlock()
	return ch
}

// Unsubscribe removes a previously subscribed channel.
func (d *DomainStats) Unsubscribe(ch chan []Stat) {
	d.mu.Lock()
	if _, ok := d.subs[ch]; ok {
		delete(d.subs, ch)
		close(ch)
	}
	d.mu.Unlock()
}

func (d *DomainStats) notify() {
	stats := d.topLocked(10)
	for ch := range d.subs {
		select {
		case ch <- stats:
		default:
		}
	}
}

// Record increments the counter for the given host.
func (d *DomainStats) Record(host string) {
	if host == "" {
		return
	}
	host = strings.ToLower(host)
	d.mu.Lock()
	d.counts[host]++
	d.notify()
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
	return d.topLocked(n)
}

func (d *DomainStats) topLocked(n int) []Stat {
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
