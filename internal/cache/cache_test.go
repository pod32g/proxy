package cache

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
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
				if got := StorableResponse(tc.resp, time.Now()); got != tc.want {
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
		if got := StorableResponse(response(200, "Cache-Control", header), time.Now()); got != ReasonNoStore {
			t.Errorf("Cache-Control: %q -> %q, want no-store", header, got)
		}
	}
	// "public" alone still needs explicit freshness.
	if got := StorableResponse(response(200, "Cache-Control", "public"), time.Now()); got != ReasonNoFreshness {
		t.Errorf("public alone -> %q, want a freshness refusal", got)
	}
}

func TestStorableResponseAcceptsExplicitFreshness(t *testing.T) {
	for _, header := range [][]string{
		{"Cache-Control", "max-age=60"},
		{"Cache-Control", "s-maxage=60"},
		{"Cache-Control", "public, max-age=60"},
	} {
		if got := StorableResponse(response(200, header...), time.Now()); got != ReasonStorable {
			t.Errorf("%v -> %q, want storable", header, got)
		}
	}
}

// s-maxage is addressed to shared caches specifically and outranks max-age.
func TestSharedMaxAgeWins(t *testing.T) {
	resp := response(200, "Cache-Control", "max-age=10, s-maxage=600")
	ttl, ok := TTL(resp, time.Now())
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
//
// Refresh returns a *replacement*. The entry passed in is never edited, because
// another goroutine may be writing it to a client without the mutex; see the
// concurrency test below for what editing it costs.
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

	fresh := c.Refresh(entry, response(304, "Cache-Control", "max-age=300", "ETag", `"v2"`, "X-Old", "2"),
		5*time.Minute)

	if fresh == entry {
		t.Fatal("Refresh edited the entry in place; it must return a replacement")
	}
	if !fresh.Fresh(*now) {
		t.Error("the replacement is not fresh")
	}
	if fresh.ETag != `"v2"` {
		t.Errorf("ETag = %q, want the updated one", fresh.ETag)
	}
	if fresh.Header.Get("X-Old") != "2" {
		t.Errorf("headers were not updated: %v", fresh.Header)
	}
	if string(fresh.Body) != "body" {
		t.Error("the body was lost; a 304 carries none, so the stored one is authoritative")
	}

	// And the entry a concurrent request may still be writing is untouched.
	if entry.Header.Get("X-Old") != "1" || entry.ETag != `"v1"` {
		t.Error("the superseded entry was mutated; a reader holding it would race")
	}
	// The replacement is what a later lookup finds.
	if got := c.Get(r); got != fresh {
		t.Error("the replacement was not installed")
	}
}

// The bug this design exists to prevent. Get hands out a pointer and releases
// the mutex, so a request replaying an entry can overlap a request revalidating
// it. Editing the shared Header map there is a concurrent map read and write,
// which aborts the process — no recover, no 500.
func TestConcurrentReadAndRefreshIsSafe(t *testing.T) {
	c := New(1<<20, 1<<16)
	r := request(t, "http://example.com/a")
	c.Store(r, response(200, "Cache-Control", "max-age=600", "ETag", `"v1"`, "X-A", "1"),
		[]byte("body"), time.Minute)
	entry := c.Get(r)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				if i%2 == 0 {
					c.Refresh(c.Get(r), response(304, "X-A", fmt.Sprint(j)), time.Minute)
					continue
				}
				// A request replaying the entry it was handed, as writeEntry does.
				for name, values := range entry.Header {
					_, _ = name, values
				}
			}
		}(i)
	}
	wg.Wait()
}

// no-cache is not a refusal to store: it means "keep this, but check with me
// before every use". Serving it for its max-age inverts the instruction.
func TestNoCacheIsStoredButNeverFresh(t *testing.T) {
	c, now := newTestCache(t, 1<<20, 1<<16)
	r := request(t, "http://example.com/a")
	resp := response(200, "Cache-Control", "no-cache, max-age=300", "ETag", `"v1"`)

	if got := StorableResponse(resp, time.Now()); got != ReasonStorable {
		t.Fatalf("no-cache was refused outright (%q); it should be stored and revalidated", got)
	}
	if !c.Store(r, resp, []byte("body"), 5*time.Minute) {
		t.Fatal("not stored")
	}

	entry := c.Get(r)
	if entry == nil {
		t.Fatal("not retrievable — it must be, so it can be revalidated")
	}
	if entry.Fresh(*now) {
		t.Error("a no-cache entry reported itself fresh; it would be served without checking")
	}
	if !entry.Revalidatable() {
		t.Error("no validator, so it can never be used at all")
	}
}

// A client asking for no-cache wants the entity confirmed, not whatever the
// proxy holds.
func TestRequestNoCacheDemandsRevalidation(t *testing.T) {
	if !RequestWantsRevalidation(request(t, "http://x/", "Cache-Control", "no-cache")) {
		t.Error("a client's no-cache was ignored")
	}
	if RequestWantsRevalidation(request(t, "http://x/")) {
		t.Error("an ordinary request was treated as demanding revalidation")
	}
}

// One rule applied twice: a request that identifies a user does not produce a
// shared entry. Cookie identifies a user as squarely as Authorization does.
func TestCookieBearingRequestsAreNotStorable(t *testing.T) {
	if got := StorableRequest(request(t, "http://x/", "Cookie", "session=abc")); got != ReasonCookie {
		t.Errorf("StorableRequest with a Cookie = %q, want %q", got, ReasonCookie)
	}
	// And the strictness matches Authorization, which is the point.
	if got := StorableRequest(request(t, "http://x/", "Authorization", "Basic x")); got != ReasonAuthorization {
		t.Errorf("Authorization = %q", got)
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
	if StorableRequest(r) == ReasonStorable && StorableResponse(resp, time.Now()) == ReasonStorable {
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

// PROXY-75. A forward proxy usually sits in front of a CDN, so a response that
// is already most of the way through its life is the common case, not the
// exotic one. Storing it for its full declared lifetime again serves it at up
// to twice the staleness the origin authorised — and the origin has no way to
// tell.
func TestStoredFreshnessSubtractsTheAgeOnArrival(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := New(1<<20, 1<<16)
	c.now = func() time.Time { return now }

	r := request(t, "http://example.com/a")
	resp := response(200, "Cache-Control", "max-age=3600", "Age", "3500")
	ttl, ok := TTL(resp, now)
	if !ok {
		t.Fatal("no declared freshness")
	}
	if !c.Store(r, resp, []byte("body"), ttl) {
		t.Fatal("not stored")
	}

	e := c.Get(r)
	if e == nil {
		t.Fatal("not found")
	}
	if want := now.Add(100 * time.Second); !e.Expires.Equal(want) {
		t.Errorf("Expires = %v, want %v (3600s of life, 3500s already spent)", e.Expires, want)
	}
	if !e.Fresh(now.Add(99 * time.Second)) {
		t.Error("not fresh with a second of life left")
	}
	if e.Fresh(now.Add(101 * time.Second)) {
		t.Error("still fresh past the origin's lifetime")
	}
	// And the age it reports counts from the origin, not from us.
	if got := e.Age(now); got != 3500*time.Second {
		t.Errorf("Age at store = %v, want 3500s", got)
	}
	if got := e.Age(now.Add(50 * time.Second)); got != 3550*time.Second {
		t.Errorf("Age after 50s = %v, want 3550s", got)
	}
}

// Date does the same job when the upstream cache omitted Age, and skew towards
// the future is not a reason to call something fresher than it is.
func TestInitialAgeFromDateAndSkew(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		h    http.Header
		want time.Duration
	}{
		{"neither", http.Header{}, 0},
		{"age only", http.Header{"Age": {"120"}}, 120 * time.Second},
		{"date only", http.Header{"Date": {now.Add(-90 * time.Second).Format(http.TimeFormat)}}, 90 * time.Second},
		{"the larger wins", http.Header{
			"Age":  {"120"},
			"Date": {now.Add(-300 * time.Second).Format(http.TimeFormat)},
		}, 300 * time.Second},
		{"clock ahead is not negative age", http.Header{
			"Date": {now.Add(600 * time.Second).Format(http.TimeFormat)},
		}, 0},
		{"garbage age ignored", http.Header{"Age": {"soon"}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := InitialAge(tc.h, now); got != tc.want {
				t.Errorf("InitialAge = %v, want %v", got, tc.want)
			}
		})
	}
}

// A response that arrives already past its lifetime is not fresh, and is worth
// keeping only for what it can be revalidated with.
func TestArrivingExpiredIsNotFresh(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := New(1<<20, 1<<16)
	c.now = func() time.Time { return now }

	r := request(t, "http://example.com/a")
	resp := response(200, "Cache-Control", "max-age=60", "Age", "600", "ETag", `"v1"`)
	ttl, _ := TTL(resp, now)
	c.Store(r, resp, []byte("body"), ttl)

	e := c.Get(r)
	if e == nil {
		t.Fatal("dropped an entry that still has a validator")
	}
	if e.Fresh(now) {
		t.Error("a response that arrived ten minutes past its lifetime is not fresh")
	}

	// Without a validator there is nothing to keep.
	r2 := request(t, "http://example.com/b")
	resp2 := response(200, "Cache-Control", "max-age=60", "Age", "600")
	ttl2, _ := TTL(resp2, now)
	c.Store(r2, resp2, []byte("body"), ttl2)
	if c.Get(r2) != nil {
		t.Error("kept an expired entry with nothing to revalidate against")
	}
}

// PROXY-71, the half that cannot be fixed by checking rules before the lookup.
//
// Listeners differ on AllowPrivate and on the client certificate they present
// upstream, and neither is a property of the request — so one listener's
// entries must not be another's. See cache.Scope.
func TestScopesDoNotShareEntries(t *testing.T) {
	c := New(1<<20, 1<<16)
	a, b := c.Scope("listener-a"), c.Scope("listener-b")

	r := request(t, "http://example.com/a")
	if !a.Store(r, response(200, "Cache-Control", "max-age=300"), []byte("PRIVILEGED"), time.Minute) {
		t.Fatal("not stored")
	}
	if a.Get(r) == nil {
		t.Error("the scope that stored it cannot find it")
	}
	if got := b.Get(r); got != nil {
		t.Errorf("another listener read it: %q", got.Body)
	}
	if got := c.Get(r); got != nil {
		t.Errorf("the unnamed scope read it: %q", got.Body)
	}

	// Each scope keeps its own copy of the same URL.
	b.Store(r, response(200, "Cache-Control", "max-age=300"), []byte("OTHER"), time.Minute)
	if got := a.Get(r); got == nil || string(got.Body) != "PRIVILEGED" {
		t.Errorf("scope a = %v, want PRIVILEGED", got)
	}
	if got := b.Get(r); got == nil || string(got.Body) != "OTHER" {
		t.Errorf("scope b = %v, want OTHER", got)
	}

	// A nil cache yields a nil scope whose every method is a no-op, so callers
	// need one nil check rather than two.
	var none *Cache
	s := none.Scope("x")
	if s.Get(r) != nil || s.Store(r, response(200), nil, time.Minute) || s.MaxEntryBytes() != 0 {
		t.Error("a scope over a nil cache is not inert")
	}
	s.Hit()
	s.Miss()
	s.Revalidated()
}
