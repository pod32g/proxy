package cache

import (
	"container/list"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Entry is one stored response.
//
// An entry is immutable once constructed. Nothing mutates one after Store
// returns it to the map, and Refresh builds a replacement rather than editing
// in place.
//
// That is not a style preference. Get hands the pointer out and releases the
// mutex, so a caller may be replaying the entry to a client while another
// request revalidates the same URL. Editing the shared Header map there is a
// concurrent map read and write, which Go does not tolerate: it aborts the
// process outright, with no recover and no 500.
//
// The two alternatives were both worse. Snapshotting on every Get allocates on
// the hot path; holding the cache mutex across the response write serialises
// the whole cache on the slowest client.
type Entry struct {
	Status  int
	Header  http.Header
	Body    []byte
	Expires time.Time

	// MustRevalidate is set when the origin said no-cache: storable, but never
	// servable without checking first.
	MustRevalidate bool

	// ETag and LastModified are what a revalidation is made with. An expired
	// entry without either is worthless and is dropped rather than kept.
	ETag         string
	LastModified string

	// vary is the request-header fingerprint this variant was stored under.
	vary string
	// varyNames is the Vary header list itself, kept so candidate lookups do
	// not have to reconstruct it or scan every entry to discover it.
	varyNames string
	// key is the map key, kept so eviction can find it from the LRU list.
	key string
	// size is the accounted cost: body plus a rough header allowance.
	size int64
}

// Fresh reports whether the entry may be served without revalidation.
//
// no-cache is not a refusal to store — it means "you may keep this, but check
// with me before every use". So such an entry is never fresh, and always takes
// the revalidation path, which is exactly the machinery a stale entry uses.
func (e *Entry) Fresh(now time.Time) bool {
	return !e.MustRevalidate && now.Before(e.Expires)
}

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

	// varyForms counts the distinct Vary header lists currently stored, so a
	// lookup builds candidate keys from that set instead of scanning every
	// entry. There are a handful across a whole estate; entries number in the
	// tens of thousands, and the scan used to run under this mutex.
	varyForms map[string]int

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
		entries:   make(map[string]*Entry),
		order:     list.New(),
		elements:  make(map[string]*list.Element),
		varyForms: make(map[string]int),
		maxBytes:  maxBytes,
		maxEntry:  maxEntry,
		now:       time.Now,
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
// The returned entry may be stale, or fresh-but-must-revalidate; the caller
// decides what to do about it. That split is deliberate — freshness is a cache
// question, but what to do about staleness is a request question.
func (c *Cache) Get(r *http.Request) *Entry {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// The unvaried key first, because it is the common case, then one key per
	// distinct Vary form currently stored — a set of a handful, not a scan of
	// every entry.
	if e := c.lookupLocked(r, ""); e != nil {
		return e
	}
	for names := range c.varyForms {
		if e := c.lookupLocked(r, varyKey(names, r.Header)); e != nil {
			return e
		}
	}
	return nil
}

// lookupLocked returns a live entry for one variant key. Callers hold mu.
func (c *Cache) lookupLocked(r *http.Request, vary string) *Entry {
	k := key(r.Method, r.URL.String(), vary)
	entry, ok := c.entries[k]
	if !ok {
		return nil
	}
	if !entry.Fresh(c.now()) && !entry.Revalidatable() {
		// Expired with nothing to revalidate against is dead weight. A
		// must-revalidate entry always lands here too, which is why it is only
		// dropped when it also has no validator — without one it could never be
		// served at all.
		c.removeLocked(k)
		return nil
	}
	c.order.MoveToFront(c.elements[k])
	return entry
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

	names := resp.Header.Get("Vary")
	vary := varyKey(names, r.Header)
	k := key(r.Method, r.URL.String(), vary)
	etag, lastMod, _ := Validator(resp.Header)

	entry := &Entry{
		Status:         resp.StatusCode,
		Header:         resp.Header.Clone(),
		Body:           body,
		Expires:        c.now().Add(ttl),
		MustRevalidate: directives(resp.Header.Get("Cache-Control")).has("no-cache"),
		ETag:           etag,
		LastModified:   lastMod,
		vary:           vary,
		varyNames:      normaliseVaryNames(names),
		key:            k,
		size:           size,
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.insertLocked(entry)

	if c.OnStore != nil {
		c.OnStore()
	}
	c.reportSizeLocked()
	return true
}

// insertLocked places an entry, replacing any it supersedes. Callers hold mu.
func (c *Cache) insertLocked(entry *Entry) {
	// Replacing releases the old entry's bytes first, or the accounting drifts
	// upward every time a URL is refreshed until the cache evicts itself empty.
	c.removeLocked(entry.key)

	c.entries[entry.key] = entry
	c.elements[entry.key] = c.order.PushFront(entry)
	c.usedBytes += entry.size
	if entry.varyNames != "" {
		c.varyForms[entry.varyNames]++
	}
	c.evictLocked()
}

// Refresh replaces a stored entry after a 304 and returns the replacement.
//
// A replacement rather than an edit: the old entry may be being written to a
// client right now, on another goroutine, without the mutex. See Entry.
//
// The caller serves the returned entry. That it is a different pointer from the
// one passed in is the whole mechanism, so callers must not keep using the old.
func (c *Cache) Refresh(old *Entry, resp *http.Response, ttl time.Duration) *Entry {
	if c == nil || old == nil {
		return old
	}

	header := old.Header.Clone()
	for name, values := range resp.Header {
		if strings.EqualFold(name, "Content-Length") {
			continue // the stored body is authoritative
		}
		header[http.CanonicalHeaderKey(name)] = values
	}

	fresh := &Entry{
		Status:         old.Status,
		Header:         header,
		Body:           old.Body, // never written after construction, so shared safely
		MustRevalidate: directives(resp.Header.Get("Cache-Control")).has("no-cache"),
		ETag:           old.ETag,
		LastModified:   old.LastModified,
		vary:           old.vary,
		varyNames:      old.varyNames,
		key:            old.key,
	}
	if etag, lastMod, ok := Validator(resp.Header); ok {
		fresh.ETag, fresh.LastModified = etag, lastMod
	}
	fresh.size = int64(len(fresh.Body)) + headerCost(header)

	c.mu.Lock()
	defer c.mu.Unlock()
	fresh.Expires = c.now().Add(ttl)
	c.insertLocked(fresh)
	c.reportSizeLocked()
	return fresh
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
	if entry.varyNames != "" {
		// Refcounted, so a form disappears from the candidate set only when the
		// last entry using it is gone. Leaving it would cost a wasted lookup
		// per request forever.
		if c.varyForms[entry.varyNames]--; c.varyForms[entry.varyNames] <= 0 {
			delete(c.varyForms, entry.varyNames)
		}
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
