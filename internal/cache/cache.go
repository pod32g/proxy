package cache

import (
	"container/list"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Entry is one stored response.
type Entry struct {
	Status  int
	Header  http.Header
	Body    []byte
	Expires time.Time

	// ETag and LastModified are what a revalidation is made with. An expired
	// entry without either is worthless and is dropped rather than kept.
	ETag         string
	LastModified string

	// vary is the request-header fingerprint this variant was stored under.
	vary string
	// key is the map key, kept so eviction can find it from the LRU list.
	key string
	// size is the accounted cost: body plus a rough header allowance.
	size int64
}

// Fresh reports whether the entry may be served without revalidation.
func (e *Entry) Fresh(now time.Time) bool { return now.Before(e.Expires) }

// Revalidatable reports whether an expired entry is worth a conditional
// request rather than a plain refetch.
func (e *Entry) Revalidatable() bool { return e.ETag != "" || e.LastModified != "" }

// Cache is a bounded in-memory response cache.
//
// Bounded by bytes rather than entries. An entry count bounds nothing useful
// when one response can be a gigabyte, and "memory stays under a figure the
// operator chose" is the only property worth promising.
type Cache struct {
	mu       sync.Mutex
	entries  map[string]*Entry
	order    *list.List // most recent at the front
	elements map[string]*list.Element

	maxBytes  int64
	maxEntry  int64
	usedBytes int64

	// now is swappable so tests drive expiry instead of sleeping.
	now func() time.Time

	// Hooks for metrics; all optional.
	OnHit        func()
	OnMiss       func()
	OnRevalidate func()
	OnStore      func()
	OnEvict      func()
	OnSize       func(bytes int64, entries int)
}

// New builds a cache. maxBytes is the total ceiling; maxEntry caps a single
// response, so one large body cannot evict everything else to make room for
// itself.
func New(maxBytes, maxEntry int64) *Cache {
	if maxEntry <= 0 || maxEntry > maxBytes {
		maxEntry = maxBytes / 10
	}
	return &Cache{
		entries:  make(map[string]*Entry),
		order:    list.New(),
		elements: make(map[string]*list.Element),
		maxBytes: maxBytes,
		maxEntry: maxEntry,
		now:      time.Now,
	}
}

// MaxEntryBytes is the largest response that will be stored.
//
// Exported because the caller has to know it *before* buffering: reading a
// large body into memory only to decide not to store it is the worst of both
// outcomes, so the handler streams past the limit instead.
func (c *Cache) MaxEntryBytes() int64 { return c.maxEntry }

// key identifies a stored response.
func key(method, url, vary string) string {
	return method + "\x00" + url + "\x00" + vary
}

// Get returns a usable entry for a request, or nil.
//
// The returned entry may be stale; the caller decides whether to revalidate.
// That split is deliberate — freshness is a cache question, but what to do
// about staleness is a request question.
func (c *Cache) Get(r *http.Request) *Entry {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Two lookups: one for responses with no Vary, one for each variant. The
	// unvaried key is tried first because it is the common case.
	for _, vary := range c.candidateVaryKeys(r) {
		k := key(r.Method, r.URL.String(), vary)
		entry, ok := c.entries[k]
		if !ok {
			continue
		}
		if !entry.Fresh(c.now()) && !entry.Revalidatable() {
			// Expired with nothing to revalidate against is dead weight.
			c.removeLocked(k)
			continue
		}
		c.order.MoveToFront(c.elements[k])
		return entry
	}
	return nil
}

// candidateVaryKeys lists the variant fingerprints worth trying for a request.
func (c *Cache) candidateVaryKeys(r *http.Request) []string {
	out := []string{""}
	// Every stored Vary header seen so far. Small in practice — a handful of
	// distinct Vary values across an estate — and it is the only way to build
	// the fingerprint, since it depends on what the *response* said.
	seen := map[string]bool{}
	for _, e := range c.entries {
		if e.vary == "" || seen[e.vary] {
			continue
		}
		seen[e.vary] = true
		if k := varyKey(headerNamesOf(e.vary), r.Header); k == e.vary {
			out = append(out, e.vary)
		}
	}
	return out
}

// headerNamesOf recovers the Vary header list from a stored fingerprint.
func headerNamesOf(fingerprint string) string {
	var names []string
	for _, line := range strings.Split(fingerprint, "\n") {
		if line == "" {
			continue
		}
		name, _, _ := strings.Cut(line, "=")
		names = append(names, name)
	}
	return strings.Join(names, ",")
}

// Store adds a response. Returns false when it was not stored.
func (c *Cache) Store(r *http.Request, resp *http.Response, body []byte, ttl time.Duration) bool {
	if c == nil {
		return false
	}
	size := int64(len(body)) + headerCost(resp.Header)
	if size > c.maxEntry {
		return false
	}

	vary := varyKey(resp.Header.Get("Vary"), r.Header)
	k := key(r.Method, r.URL.String(), vary)
	etag, lastMod, _ := Validator(resp.Header)

	entry := &Entry{
		Status:       resp.StatusCode,
		Header:       resp.Header.Clone(),
		Body:         body,
		Expires:      c.now().Add(ttl),
		ETag:         etag,
		LastModified: lastMod,
		vary:         vary,
		key:          k,
		size:         size,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Replacing an existing entry releases its bytes first, or the accounting
	// drifts upward every time a URL is refreshed.
	c.removeLocked(k)

	c.entries[k] = entry
	c.elements[k] = c.order.PushFront(entry)
	c.usedBytes += size
	c.evictLocked()

	if c.OnStore != nil {
		c.OnStore()
	}
	c.reportSizeLocked()
	return true
}

// Refresh extends a stored entry after a 304, which is the entire economy of a
// validator: the origin sent headers rather than a body.
func (c *Cache) Refresh(e *Entry, resp *http.Response, ttl time.Duration) {
	if c == nil || e == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e.Expires = c.now().Add(ttl)
	// A 304 may carry updated headers, which supersede the stored ones.
	for name, values := range resp.Header {
		if strings.EqualFold(name, "Content-Length") {
			continue // the stored body is authoritative
		}
		e.Header[http.CanonicalHeaderKey(name)] = values
	}
	if etag, lastMod, _ := Validator(resp.Header); etag != "" || lastMod != "" {
		e.ETag, e.LastModified = etag, lastMod
	}
}

// removeLocked drops an entry and releases its bytes. Callers hold mu.
func (c *Cache) removeLocked(k string) {
	entry, ok := c.entries[k]
	if !ok {
		return
	}
	c.usedBytes -= entry.size
	delete(c.entries, k)
	if el, ok := c.elements[k]; ok {
		c.order.Remove(el)
		delete(c.elements, k)
	}
}

// evictLocked drops least-recently-used entries until the cache is under its
// ceiling. Callers hold mu.
func (c *Cache) evictLocked() {
	for c.usedBytes > c.maxBytes {
		oldest := c.order.Back()
		if oldest == nil {
			// Nothing left to drop. Only reachable if the accounting is wrong,
			// so reset rather than spin.
			c.usedBytes = 0
			return
		}
		entry := oldest.Value.(*Entry)
		c.removeLocked(entry.key)
		if c.OnEvict != nil {
			c.OnEvict()
		}
	}
}

func (c *Cache) reportSizeLocked() {
	if c.OnSize != nil {
		c.OnSize(c.usedBytes, len(c.entries))
	}
}

// headerCost is a rough allowance so header-heavy responses are not accounted
// as free. Exact accounting of a Go map is not possible and not worth it; the
// point is that the total tracks reality closely enough to bound it.
func headerCost(h http.Header) int64 {
	var n int64
	for name, values := range h {
		n += int64(len(name)) + 32
		for _, v := range values {
			n += int64(len(v))
		}
	}
	return n
}

// Stats reports current occupancy.
func (c *Cache) Stats() (bytes int64, entries int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usedBytes, len(c.entries)
}

// Hit, Miss and Revalidated report outcomes to the metrics hooks.
func (c *Cache) Hit() {
	if c != nil && c.OnHit != nil {
		c.OnHit()
	}
}

func (c *Cache) Miss() {
	if c != nil && c.OnMiss != nil {
		c.OnMiss()
	}
}

func (c *Cache) Revalidated() {
	if c != nil && c.OnRevalidate != nil {
		c.OnRevalidate()
	}
}

// TTL returns how long a response may be cached, and whether it may be at all.
func TTL(resp *http.Response) (time.Duration, bool) {
	return freshness(resp, directives(resp.Header.Get("Cache-Control")))
}
