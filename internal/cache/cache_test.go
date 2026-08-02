package cache

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func request(t *testing.T, url string, headers ...string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

func response(status int, headers ...string) *http.Response {
	h := http.Header{}
	for i := 0; i+1 < len(headers); i += 2 {
		h.Add(headers[i], headers[i+1])
	}
	return &http.Response{StatusCode: status, Header: h}
}

// The criterion everything else is arranged around. Each rule is asserted on
// its own, because a bundle that passes tells you nothing about which rule is
// carrying it — and a cache that serves one user's content to another is not a
// degraded cache, it is a disclosure.
func TestNeverStored(t *testing.T) {
	t.Run("requests", func(t *testing.T) {
		for name, tc := range map[string]struct {
			req  *http.Request
			want Reason
		}{
			"Authorization": {
				request(t, "http://x/", "Authorization", "Basic YWRtaW46cA=="),
				ReasonAuthorization,
			},
			"Proxy-Authorization": {
				request(t, "http://x/", "Proxy-Authorization", "Basic YWRtaW46cA=="),
				ReasonAuthorization,
			},
			"request no-store": {
				request(t, "http://x/", "Cache-Control", "no-store"),
				ReasonRequestNoStore,
			},
		} {
			t.Run(name, func(t *testing.T) {
				if got := StorableRequest(tc.req); got != tc.want {
					t.Errorf("StorableRequest = %q, want %q", got, tc.want)
				}
			})
		}

		// POST and friends are not cacheable regardless of headers.
		for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "CONNECT"} {
			r, _ := http.NewRequest(method, "http://x/", nil)
			if got := StorableRequest(r); got != ReasonMethod {
				t.Errorf("%s: got %q, want %q", method, got, ReasonMethod)
			}
		}
	})

	t.Run("responses", func(t *testing.T) {
		for name, tc := range map[string]struct {
			resp *http.Response
			want Reason
		}{
			"no-store": {
				response(200, "Cache-Control", "max-age=60, no-store"), ReasonNoStore,
			},
			"private": {
				response(200, "Cache-Control", "max-age=60, private"), ReasonPrivate,
			},
			"Set-Cookie": {
				response(200, "Cache-Control", "max-age=60", "Set-Cookie", "session=abc"),
				ReasonSetCookie,
			},
			"Vary: *": {
				response(200, "Cache-Control", "max-age=60", "Vary", "*"), ReasonVaryAll,
			},
			"no explicit freshness": {
				response(200, "Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT"),
				ReasonNoFreshness,
			},
			"uncacheable status": {
				response(500, "Cache-Control", "max-age=60"), ReasonStatus,
			},
			"expired Expires": {
				response(200, "Expires", "Mon, 01 Jan 2001 00:00:00 GMT"), ReasonNoFreshness,
			},
			"unparseable Expires": {
				response(200, "Expires", "not a date"), ReasonNoFreshness,
			},
		} {
			t.Run(name, func(t *testing.T) {
				if got := StorableResponse(tc.resp); got != tc.want {
					t.Errorf("StorableResponse = %q, want %q", got, tc.want)
				}
			})
		}
	})
}

// Directives are matched case-insensitively and are not fooled by a value that
// merely contains the word.
func TestDirectiveParsing(t *testing.T) {
	for _, header := range []string{
		"no-store", "NO-STORE", "max-age=60, no-store", " no-store , public ",
	} {
		if got := StorableResponse(response(200, "Cache-Control", header)); got != ReasonNoStore {
			t.Errorf("Cache-Control: %q -> %q, want no-store", header, got)
		}
	}
	// "public" alone still needs explicit freshness.
	if got := StorableResponse(response(200, "Cache-Control", "public")); got != ReasonNoFreshness {
		t.Errorf("public alone -> %q, want a freshness refusal", got)
	}
}

func TestStorableResponseAcceptsExplicitFreshness(t *testing.T) {
	for _, header := range [][]string{
		{"Cache-Control", "max-age=60"},
		{"Cache-Control", "s-maxage=60"},
		{"Cache-Control", "public, max-age=60"},
	} {
		if got := StorableResponse(response(200, header...)); got != ReasonStorable {
			t.Errorf("%v -> %q, want storable", header, got)
		}
	}
}

// s-maxage is addressed to shared caches specifically and outranks max-age.
func TestSharedMaxAgeWins(t *testing.T) {
	resp := response(200, "Cache-Control", "max-age=10, s-maxage=600")
	ttl, ok := TTL(resp)
	if !ok {
		t.Fatal("not cacheable")
	}
	if ttl != 600*time.Second {
		t.Errorf("ttl = %v, want the s-maxage 600s", ttl)
	}
}

func newTestCache(t *testing.T, maxBytes, maxEntry int64) (*Cache, *time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(maxBytes, maxEntry)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestStoreAndGet(t *testing.T) {
	c, _ := newTestCache(t, 1<<20, 1<<16)
	r := request(t, "http://example.com/a")
	resp := response(200, "Cache-Control", "max-age=60")

	if !c.Store(r, resp, []byte("body"), time.Minute) {
		t.Fatal("Store refused a cacheable response")
	}
	entry := c.Get(r)
	if entry == nil {
		t.Fatal("no entry returned")
	}
	if string(entry.Body) != "body" || entry.Status != 200 {
		t.Errorf("got %+v", entry)
	}
	// A different URL is a different entry.
	if c.Get(request(t, "http://example.com/b")) != nil {
		t.Error("an unrelated URL matched")
	}
}

func TestExpiredEntryWithoutValidatorIsDropped(t *testing.T) {
	c, now := newTestCache(t, 1<<20, 1<<16)
	r := request(t, "http://example.com/a")
	c.Store(r, response(200, "Cache-Control", "max-age=60"), []byte("body"), time.Minute)

	*now = now.Add(2 * time.Minute)
	if got := c.Get(r); got != nil {
		t.Error("an expired entry with nothing to revalidate against was kept")
	}
	if bytes, entries := c.Stats(); entries != 0 || bytes != 0 {
		t.Errorf("occupancy = %d bytes / %d entries after dropping", bytes, entries)
	}
}

// An expired entry that *can* be revalidated is kept and returned stale, so the
// caller can make a conditional request instead of refetching the body.
func TestExpiredEntryWithValidatorIsKeptForRevalidation(t *testing.T) {
	c, now := newTestCache(t, 1<<20, 1<<16)
	r := request(t, "http://example.com/a")
	c.Store(r, response(200, "Cache-Control", "max-age=60", "ETag", `"v1"`),
		[]byte("body"), time.Minute)

	*now = now.Add(2 * time.Minute)
	entry := c.Get(r)
	if entry == nil {
		t.Fatal("a revalidatable entry was dropped")
	}
	if entry.Fresh(*now) {
		t.Error("the entry reported itself fresh")
	}
	if !entry.Revalidatable() {
		t.Error("the entry lost its validator")
	}
}

// A 304 refreshes rather than discards — the whole economy of a validator.
func TestRefreshExtendsAndUpdatesHeaders(t *testing.T) {
	c, now := newTestCache(t, 1<<20, 1<<16)
	r := request(t, "http://example.com/a")
	c.Store(r, response(200, "Cache-Control", "max-age=60", "ETag", `"v1"`, "X-Old", "1"),
		[]byte("body"), time.Minute)

	*now = now.Add(2 * time.Minute)
	entry := c.Get(r)
	if entry == nil {
		t.Fatal("no entry")
	}

	c.Refresh(entry, response(304, "Cache-Control", "max-age=300", "ETag", `"v2"`, "X-Old", "2"),
		5*time.Minute)

	if !entry.Fresh(*now) {
		t.Error("the entry was not refreshed")
	}
	if entry.ETag != `"v2"` {
		t.Errorf("ETag = %q, want the updated one", entry.ETag)
	}
	if entry.Header.Get("X-Old") != "2" {
		t.Errorf("headers were not updated: %v", entry.Header)
	}
	if string(entry.Body) != "body" {
		t.Error("the body was lost; a 304 carries none, so the stored one is authoritative")
	}
}

// The criterion: bounded memory, tested with a working set larger than the cap.
func TestBoundedUnderAnOversizedWorkingSet(t *testing.T) {
	const cap = 64 << 10
	c, _ := newTestCache(t, cap, cap/4)

	body := make([]byte, 4<<10)
	var evictions int
	c.OnEvict = func() { evictions++ }

	// Roughly ten times the ceiling.
	for i := 0; i < 160; i++ {
		r := request(t, fmt.Sprintf("http://example.com/%d", i))
		c.Store(r, response(200, "Cache-Control", "max-age=60"), body, time.Minute)

		if bytes, _ := c.Stats(); bytes > cap {
			t.Fatalf("after %d stores the cache held %d bytes, over the %d cap", i+1, bytes, cap)
		}
	}
	if evictions == 0 {
		t.Error("nothing was evicted despite a working set ten times the cap")
	}

	// And the recent entries are the survivors.
	if c.Get(request(t, "http://example.com/159")) == nil {
		t.Error("the most recent entry was evicted")
	}
	if c.Get(request(t, "http://example.com/0")) != nil {
		t.Error("the oldest entry survived a full turnover")
	}
}

// One large response must not evict everything to make room for itself.
func TestOversizedResponseIsNotStored(t *testing.T) {
	c, _ := newTestCache(t, 1<<20, 1<<10)
	r := request(t, "http://example.com/big")
	if c.Store(r, response(200, "Cache-Control", "max-age=60"), make([]byte, 4<<10), time.Minute) {
		t.Error("a response over the per-entry limit was stored")
	}
	if bytes, entries := c.Stats(); entries != 0 || bytes != 0 {
		t.Errorf("occupancy = %d bytes / %d entries", bytes, entries)
	}
}

// Re-storing a URL must release the old entry's bytes, or the accounting drifts
// upward on every refresh until the cache evicts everything.
func TestReplacingAnEntryReleasesItsBytes(t *testing.T) {
	c, _ := newTestCache(t, 1<<20, 1<<16)
	r := request(t, "http://example.com/a")
	body := make([]byte, 1<<10)

	for i := 0; i < 50; i++ {
		c.Store(r, response(200, "Cache-Control", "max-age=60"), body, time.Minute)
	}
	bytes, entries := c.Stats()
	if entries != 1 {
		t.Errorf("entries = %d, want 1", entries)
	}
	if bytes > 2<<10 {
		t.Errorf("occupancy = %d bytes after 50 refreshes of one 1KB entry", bytes)
	}
}

// Vary keeps variants apart, or a gzip body reaches a client that cannot decode
// it and an English page reaches one that asked for Japanese.
func TestVaryKeepsVariantsApart(t *testing.T) {
	c, _ := newTestCache(t, 1<<20, 1<<16)

	gzipReq := request(t, "http://example.com/a", "Accept-Encoding", "gzip")
	plainReq := request(t, "http://example.com/a", "Accept-Encoding", "identity")
	resp := response(200, "Cache-Control", "max-age=60", "Vary", "Accept-Encoding")

	c.Store(gzipReq, resp, []byte("GZIPPED"), time.Minute)

	if e := c.Get(gzipReq); e == nil || string(e.Body) != "GZIPPED" {
		t.Errorf("the matching variant was not returned: %v", e)
	}
	if e := c.Get(plainReq); e != nil {
		t.Errorf("a different variant was served %q", e.Body)
	}

	c.Store(plainReq, resp, []byte("PLAIN"), time.Minute)
	if e := c.Get(plainReq); e == nil || string(e.Body) != "PLAIN" {
		t.Errorf("the second variant was not stored separately: %v", e)
	}
	if e := c.Get(gzipReq); e == nil || string(e.Body) != "GZIPPED" {
		t.Errorf("storing a variant clobbered the other: %v", e)
	}
}

func TestMetricHooks(t *testing.T) {
	c, _ := newTestCache(t, 1<<20, 1<<16)
	var hits, misses, revals, stores int
	c.OnHit = func() { hits++ }
	c.OnMiss = func() { misses++ }
	c.OnRevalidate = func() { revals++ }
	c.OnStore = func() { stores++ }

	c.Store(request(t, "http://example.com/a"), response(200, "Cache-Control", "max-age=60"),
		[]byte("b"), time.Minute)
	c.Hit()
	c.Miss()
	c.Revalidated()

	if stores != 1 || hits != 1 || misses != 1 || revals != 1 {
		t.Errorf("stores=%d hits=%d misses=%d revalidations=%d", stores, hits, misses, revals)
	}
}

func TestNilCacheIsHarmless(t *testing.T) {
	var c *Cache
	if c.Get(request(t, "http://x/")) != nil {
		t.Error("nil cache returned an entry")
	}
	if c.Store(request(t, "http://x/"), response(200), nil, time.Minute) {
		t.Error("nil cache stored something")
	}
	c.Refresh(nil, response(304), time.Minute)
	c.Hit()
	c.Miss()
	c.Revalidated()
	if b, e := c.Stats(); b != 0 || e != 0 {
		t.Errorf("nil cache reported %d/%d", b, e)
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	c := New(1<<20, 1<<16)
	body := make([]byte, 512)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				r := request(t, fmt.Sprintf("http://example.com/%d", j%20))
				c.Store(r, response(200, "Cache-Control", "max-age=60"), body, time.Minute)
				c.Get(r)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if bytes, _ := c.Stats(); bytes > 1<<20 {
		t.Errorf("concurrent use exceeded the cap: %d bytes", bytes)
	}
}

// A stored Authorization-bearing response would be the disclosure this whole
// design exists to prevent, so it is asserted end to end through the store as
// well as through the predicate.
func TestAuthenticatedRequestNeverProducesAnEntry(t *testing.T) {
	c, _ := newTestCache(t, 1<<20, 1<<16)
	r := request(t, "http://example.com/private", "Authorization", "Basic YWRtaW46cA==")

	if StorableRequest(r) == ReasonStorable {
		t.Fatal("an authenticated request was considered storable")
	}
	// Even the most permissive response headers must not change that.
	resp := response(200, "Cache-Control", "public, max-age=31536000")
	if StorableRequest(r) == ReasonStorable && StorableResponse(resp) == ReasonStorable {
		t.Error("public, max-age would have cached an authenticated response")
	}
	if _, entries := c.Stats(); entries != 0 {
		t.Error("something was stored")
	}
}

func TestVaryKeyIsOrderStableAndCaseInsensitive(t *testing.T) {
	h := http.Header{}
	h.Set("Accept-Encoding", "gzip")
	h.Set("Accept-Language", "en")

	a := varyKey("Accept-Encoding, Accept-Language", h)
	b := varyKey("accept-encoding,accept-language", h)
	if a != b {
		t.Errorf("case changed the fingerprint:\n%q\n%q", a, b)
	}
	if !strings.Contains(a, "accept-encoding=gzip") {
		t.Errorf("fingerprint = %q", a)
	}
}
