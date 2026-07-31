package server

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// The tracked set is keyed by hostnames the client chooses, so it needs a
	// ceiling or a single client can grow it without limit. When the ceiling is
	// hit the tail is dropped: this panel answers "what are the top sites",
	// which the long tail of once-seen hosts does not contribute to.
	maxTrackedHosts = 20000
	pruneToHosts    = 10000

	// Recomputing the top-N means sorting the whole table, so it is throttled
	// rather than done per request. A live panel that lags by a quarter second
	// is indistinguishable from one that does not.
	notifyInterval = 250 * time.Millisecond
)

// DomainStats tracks the number of requests per host.
type DomainStats struct {
	mu         sync.Mutex
	counts     map[string]int
	subs       map[chan []Stat]struct{}
	lastNotify time.Time
	// pruned records whether the tail has ever been dropped, so callers can
	// tell an exact table from an approximate one.
	pruned bool
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

// notifyLocked pushes a fresh top-N to subscribers. The caller holds mu.
func (d *DomainStats) notifyLocked() {
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
	defer d.mu.Unlock()

	d.counts[host]++

	if len(d.counts) > maxTrackedHosts {
		d.pruneLocked()
	}
	// Nobody watching means nothing to compute. With a watcher, recompute at
	// most once per interval — this used to sort the entire table on every
	// single request, which cost over a millisecond once the table was large.
	if len(d.subs) == 0 {
		return
	}
	now := time.Now()
	if now.Sub(d.lastNotify) < notifyInterval {
		return
	}
	d.lastNotify = now
	d.notifyLocked()
}

// pruneLocked drops the least-seen hosts, keeping the table bounded. Counts for
// surviving hosts are preserved; dropped hosts start from zero if seen again.
func (d *DomainStats) pruneLocked() {
	keep := d.topLocked(pruneToHosts)
	counts := make(map[string]int, pruneToHosts)
	for _, s := range keep {
		counts[s.Host] = s.Count
	}
	d.counts = counts
	d.pruned = true
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

// Approximate reports whether the tail has been dropped, meaning the table no
// longer accounts for every host seen.
func (d *DomainStats) Approximate() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pruned
}

func (d *DomainStats) topLocked(n int) []Stat {
	out := make([]Stat, 0, len(d.counts))
	for h, c := range d.counts {
		out = append(out, Stat{Host: h, Count: c})
	}
	// Ties broken by host so the order is stable rather than map-random, which
	// otherwise makes the live panel jitter between equal-count entries.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
