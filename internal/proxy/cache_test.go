package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/pod32g/proxy/internal/cache"
	"github.com/pod32g/proxy/internal/header"
)

// cachingProxy wires a real cache into a real handler. The predicates are unit
// tested; this is about whether anything calls them.
func cachingProxy(t *testing.T, c *cache.Cache) http.Handler {
	t.Helper()
	return NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts(), Cache: c})
}

func fetch(t *testing.T, h http.Handler, url string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCacheHitAvoidsTheOrigin(t *testing.T) {
	var hits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=300")
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))

	first := fetch(t, h, origin.URL+"/a")
	if first.Body.String() != "ORIGIN" {
		t.Fatalf("first fetch: %q", first.Body.String())
	}
	if got := first.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first fetch X-Cache = %q, want MISS", got)
	}

	second := fetch(t, h, origin.URL+"/a")
	if second.Body.String() != "ORIGIN" {
		t.Errorf("second fetch: %q", second.Body.String())
	}
	if got := second.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second fetch X-Cache = %q, want HIT", got)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("the origin was hit %d times, want 1", n)
	}
}

// The rule this whole design exists for, asserted through the handler rather
// than the predicate: an authenticated request must never produce an entry
// another client could be served.
func TestAuthenticatedResponseIsNeverServedToAnother(t *testing.T) {
	var hits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Deliberately the most permissive caching headers an origin can send.
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		if auth := r.Header.Get("Authorization"); auth != "" {
			io.WriteString(w, "SECRET FOR "+auth)
			return
		}
		io.WriteString(w, "ANONYMOUS")
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))

	authed := fetch(t, h, origin.URL+"/private", "Authorization", "Basic YWxpY2U6cA==")
	if authed.Body.String() != "SECRET FOR Basic YWxpY2U6cA==" {
		t.Fatalf("authenticated fetch: %q", authed.Body.String())
	}

	// A different client, no credentials, same URL.
	anon := fetch(t, h, origin.URL+"/private")
	if anon.Body.String() != "ANONYMOUS" {
		t.Fatalf("one client was served another's content: %q", anon.Body.String())
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("origin hits = %d, want 2 — the authenticated response was cached", n)
	}
}

// Each refusal asserted through the handler, so a rule that is checked but
// never reached would still fail here.
func TestUncacheableResponsesAlwaysReachTheOrigin(t *testing.T) {
	for name, headers := range map[string]map[string]string{
		"no-store":     {"Cache-Control": "max-age=300, no-store"},
		"private":      {"Cache-Control": "max-age=300, private"},
		"Set-Cookie":   {"Cache-Control": "max-age=300", "Set-Cookie": "session=abc"},
		"Vary: *":      {"Cache-Control": "max-age=300", "Vary": "*"},
		"no freshness": {"Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT"},
	} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
				io.WriteString(w, "BODY")
			}))
			defer origin.Close()

			h := cachingProxy(t, cache.New(1<<20, 1<<16))
			fetch(t, h, origin.URL+"/x")
			second := fetch(t, h, origin.URL+"/x")

			if n := hits.Load(); n != 2 {
				t.Errorf("origin hits = %d, want 2 — this response was cached", n)
			}
			if got := second.Header().Get("X-Cache"); got == "HIT" {
				t.Error("served from cache")
			}
		})
	}
}

// A stale entry with a validator becomes a conditional request, and a 304
// refreshes it — which is the entire economy of holding a validator.
func TestStaleEntryIsRevalidatedNotRefetched(t *testing.T) {
	var conditionals, fullFetches atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		// One second, so the entry is stale almost immediately.
		w.Header().Set("Cache-Control", "max-age=0")
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditionals.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fullFetches.Add(1)
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))

	if got := fetch(t, h, origin.URL+"/a").Body.String(); got != "ORIGIN" {
		t.Fatalf("first fetch: %q", got)
	}

	second := fetch(t, h, origin.URL+"/a")
	if got := second.Body.String(); got != "ORIGIN" {
		t.Errorf("revalidated fetch body = %q, want the stored body", got)
	}
	if got := second.Header().Get("X-Cache"); got != "REVALIDATED" {
		t.Errorf("X-Cache = %q, want REVALIDATED", got)
	}
	if conditionals.Load() != 1 {
		t.Errorf("conditional requests = %d, want 1", conditionals.Load())
	}
	if fullFetches.Load() != 1 {
		t.Errorf("full fetches = %d, want 1 — the body was refetched", fullFetches.Load())
	}
}

// A response larger than the per-entry limit still has to reach the client
// intact; it is simply not stored.
func TestOversizedResponseIsStreamedThroughUncached(t *testing.T) {
	body := make([]byte, 64<<10)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Write(body)
	}))
	defer origin.Close()

	c := cache.New(1<<20, 1<<10) // per-entry limit far below the body
	h := cachingProxy(t, c)

	got := fetch(t, h, origin.URL+"/big")
	if got.Body.Len() != len(body) {
		t.Fatalf("body truncated: got %d bytes, want %d", got.Body.Len(), len(body))
	}
	if string(got.Body.Bytes()) != string(body) {
		t.Error("body corrupted")
	}
	if _, entries := c.Stats(); entries != 0 {
		t.Errorf("%d entries stored despite exceeding the per-entry limit", entries)
	}
}

// With no cache configured nothing changes — no buffering, no header, no
// behaviour difference at all.
func TestNoCacheConfiguredIsUnchanged(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	h := cachingProxy(t, nil)
	got := fetch(t, h, origin.URL+"/a")
	if got.Body.String() != "ORIGIN" {
		t.Errorf("body = %q", got.Body.String())
	}
	if v := got.Header().Get("X-Cache"); v != "" {
		t.Errorf("X-Cache = %q with no cache configured", v)
	}
}

// Variants are kept apart through the handler too.
func TestVaryIsHonouredEndToEnd(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Vary", "Accept-Language")
		fmt.Fprintf(w, "lang=%s", r.Header.Get("Accept-Language"))
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))

	fetch(t, h, origin.URL+"/a", "Accept-Language", "en")
	ja := fetch(t, h, origin.URL+"/a", "Accept-Language", "ja")
	if ja.Body.String() != "lang=ja" {
		t.Errorf("a Japanese request was served %q", ja.Body.String())
	}

	en := fetch(t, h, origin.URL+"/a", "Accept-Language", "en")
	if en.Body.String() != "lang=en" {
		t.Errorf("an English request was served %q", en.Body.String())
	}
	if got := en.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("the English variant was not cached: X-Cache = %q", got)
	}
}

// A hit and a miss must be indistinguishable to the client. Rules used to be
// applied before storing, so a hit replayed whatever the rules said when the
// entry was created and a rule change never reached cached URLs.
func TestResponseRulesApplyToHitsAndMisses(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("X-Origin", "yes")
		io.WriteString(w, "BODY")
	}))
	defer origin.Close()

	rules := &atomicRules{}
	rules.set(t, "response set X-Via: first")

	c := cache.New(1<<20, 1<<16)
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(), Cache: c,
			HeaderRules: rules.get,
		})

	miss := fetch(t, h, origin.URL+"/a")
	if got := miss.Header().Get("X-Via"); got != "first" {
		t.Fatalf("miss X-Via = %q", got)
	}

	hit := fetch(t, h, origin.URL+"/a")
	if hit.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected a hit, got %q", hit.Header().Get("X-Cache"))
	}
	if got := hit.Header().Get("X-Via"); got != "first" {
		t.Errorf("hit X-Via = %q — rules did not apply to a hit", got)
	}

	// Change the rule. A cached entry must follow it immediately.
	rules.set(t, "response set X-Via: second")

	after := fetch(t, h, origin.URL+"/a")
	if after.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected a hit, got %q", after.Header().Get("X-Cache"))
	}
	if got := after.Header().Get("X-Via"); got != "second" {
		t.Errorf("hit X-Via = %q after a rule change — the rule was baked in at store time", got)
	}
	// And the origin's own header still comes through.
	if after.Header().Get("X-Origin") != "yes" {
		t.Error("the stored entry lost the origin's headers")
	}
}

// A cookie-bearing request identifies a user just as an Authorization header
// does, and must not produce an entry another client can be served.
func TestCookieBearingResponseIsNotShared(t *testing.T) {
	var hits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		if c := r.Header.Get("Cookie"); c != "" {
			io.WriteString(w, "PERSONAL FOR "+c)
			return
		}
		io.WriteString(w, "ANONYMOUS")
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))

	personal := fetch(t, h, origin.URL+"/dashboard", "Cookie", "session=alice")
	if personal.Body.String() != "PERSONAL FOR session=alice" {
		t.Fatalf("cookied fetch: %q", personal.Body.String())
	}
	anon := fetch(t, h, origin.URL+"/dashboard")
	if anon.Body.String() != "ANONYMOUS" {
		t.Fatalf("one user was served another's page: %q", anon.Body.String())
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("origin hits = %d, want 2", n)
	}
}

// no-cache means "keep this, but check with me first". Serving it for its
// max-age inverts the instruction.
func TestNoCacheRevalidatesEveryTime(t *testing.T) {
	var conditionals, full atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Cache-Control", "no-cache, max-age=300")
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditionals.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		io.WriteString(w, "BODY")
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))

	fetch(t, h, origin.URL+"/a")
	for i := 0; i < 3; i++ {
		got := fetch(t, h, origin.URL+"/a")
		if got.Body.String() != "BODY" {
			t.Errorf("body = %q", got.Body.String())
		}
		if got.Header().Get("X-Cache") == "HIT" {
			t.Fatal("a no-cache response was served without checking the origin")
		}
	}
	if conditionals.Load() != 3 {
		t.Errorf("conditional requests = %d, want 3", conditionals.Load())
	}
	if full.Load() != 1 {
		t.Errorf("full fetches = %d, want 1 — the body was refetched", full.Load())
	}
}

// A client asking for no-cache wants the entity confirmed, not whatever is held.
func TestClientNoCacheForcesRevalidation(t *testing.T) {
	var conditionals atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Cache-Control", "max-age=300")
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditionals.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, "BODY")
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))
	fetch(t, h, origin.URL+"/a")

	if got := fetch(t, h, origin.URL+"/a"); got.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("an ordinary second fetch should hit, got %q", got.Header().Get("X-Cache"))
	}
	forced := fetch(t, h, origin.URL+"/a", "Cache-Control", "no-cache")
	if forced.Header().Get("X-Cache") == "HIT" {
		t.Error("a client's no-cache was ignored")
	}
	if conditionals.Load() != 1 {
		t.Errorf("conditional requests = %d, want 1", conditionals.Load())
	}
}

// atomicRules stands in for configuration that changes under a running handler.
type atomicRules struct {
	v atomic.Pointer[header.RuleSet]
}

func (a *atomicRules) set(t *testing.T, text string) {
	t.Helper()
	set, err := header.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	a.v.Store(set)
}

func (a *atomicRules) get(string) *header.RuleSet { return a.v.Load() }
