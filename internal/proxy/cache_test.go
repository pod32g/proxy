package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pod32g/proxy/internal/cache"
	"github.com/pod32g/proxy/internal/header"
	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/server"
	log "github.com/pod32g/simple-logger"
)

// cachingProxy wires a real cache into a real handler. The predicates are unit
// tested; this is about whether anything calls them.
func cachingProxy(t *testing.T, c *cache.Cache) http.Handler {
	t.Helper()
	return NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts(), Cache: c.Scope("test")})
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
			AllowPrivate: true, ConnectPorts: allPorts(), Cache: c.Scope("test"),
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

// atomicDestinationRules is a destination rule set an operator can change
// mid-flight, which is the whole point: Policy.Rules is a function so that an
// edit applies to the next request rather than the next restart.
type atomicDestinationRules struct{ v atomic.Value }

func (a *atomicDestinationRules) set(t *testing.T, text string) {
	t.Helper()
	if text == "" {
		a.v.Store((*policy.RuleSet)(nil))
		return
	}
	set, err := policy.Parse(text)
	if err != nil {
		t.Fatalf("policy.Parse(%q): %v", text, err)
	}
	a.v.Store(set)
}

func (a *atomicDestinationRules) get(string) *policy.RuleSet {
	set, _ := a.v.Load().(*policy.RuleSet)
	return set
}

// PROXY-71. A fresh cache hit answered above every check there was, so a
// destination the operator had denied kept being served out of the cache — with
// the refusal counter untouched and X-Cache: HIT the only trace that anything
// had happened at all.
//
// This is the same shape as PROXY-70, where response header rules were skipped
// on a hit for the same reason: the early return sits above the code that does
// the work. There it produced a stale header. Here it produced a bypassed
// security control.
func TestACacheHitIsStillSubjectToTheDestinationPolicy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		io.WriteString(w, "SECRET")
	}))
	defer origin.Close()

	rules := &atomicDestinationRules{}
	rules.set(t, "")

	var refusals atomic.Int64
	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(),
			Cache: cache.New(1<<20, 1<<16).Scope("test"),
			Rules: rules.get,
		},
		Observer{Denied: func(DeniedScope) { refusals.Add(1) }})

	if got := fetch(t, h, origin.URL+"/a"); got.Code != http.StatusOK {
		t.Fatalf("the priming fetch got %d", got.Code)
	}
	if got := fetch(t, h, origin.URL+"/a"); got.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("the second fetch was not a hit: %s", got.Header().Get("X-Cache"))
	}

	rules.set(t, "deny all")
	denied := fetch(t, h, origin.URL+"/a")
	if denied.Code != http.StatusForbidden {
		t.Errorf("denied destination served %d %q (X-Cache: %s), want 403",
			denied.Code, denied.Body.String(), denied.Header().Get("X-Cache"))
	}
	// Counted as a refusal, so it is visible as one rather than as a served
	// request. A silent bypass is what made this hard to see.
	if refusals.Load() != 1 {
		t.Errorf("refusals = %d, want 1", refusals.Load())
	}
}

// PROXY-75, the serving half. RFC 9111 §5.1: a downstream cache with no Age to
// go on restarts the clock from zero and extends the lifetime again, so the
// error compounds at every hop.
//
// The origin sends both an Age and an older Date, and they disagree. That is
// deliberate: writeEntry replays the stored headers, so a test against an
// origin that sent Age: 60 would pass on the copied header whether or not this
// proxy computes anything at all. Only the value derived from the *larger* of
// the two can distinguish a measurement from an echo.
func TestHitsCarryAnAgeHeader(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		w.Header().Set("Age", "60")
		w.Header().Set("Date", time.Now().Add(-300*time.Second).UTC().Format(http.TimeFormat))
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))
	fetch(t, h, origin.URL+"/a")

	hit := fetch(t, h, origin.URL+"/a")
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("X-Cache = %q, want HIT", got)
	}
	raw := hit.Header().Get("Age")
	age, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("Age = %q: %v", raw, err)
	}
	if age == 60 {
		t.Fatalf("Age = 60: the origin's header was replayed, not measured")
	}
	// Counted from when the origin generated the response, not from when this
	// cache first saw it.
	if age < 300 || age > 305 {
		t.Errorf("Age = %d, want ~300 — the age on arrival plus time held here", age)
	}
}

// A rule must not be able to overwrite Age: it is a measurement, and a
// downstream cache extends a lifetime on the strength of it.
func TestAgeSurvivesResponseHeaderRules(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Age", "120")
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	rules := &atomicRules{}
	rules.set(t, "response set Age: 0")

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{
			AllowPrivate: true, ConnectPorts: allPorts(),
			Cache:       cache.New(1<<20, 1<<16).Scope("test"),
			HeaderRules: rules.get,
		})
	fetch(t, h, origin.URL+"/a")

	hit := fetch(t, h, origin.URL+"/a")
	if got := hit.Header().Get("Age"); got == "0" {
		t.Error("a rule overwrote Age; downstream caches would treat the entry as new")
	}
}

// PROXY-79. A HEAD is stored with no body, by definition. Recomputing
// Content-Length from that body — right and necessary for a GET, where the
// stored body is what will be written — reported 0 for every HEAD hit while the
// miss before it reported the real size. Nothing errors on that; the client
// simply believes the resource is empty, which is most of what HEAD is for.
func TestHeadHitReportsTheEntitysLength(t *testing.T) {
	const body = "SECRET-FROM-ORIGIN"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		io.WriteString(w, body)
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))
	head := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodHead, origin.URL+"/a", nil)
		req.RemoteAddr = "10.1.2.3:5000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	miss := head()
	if got := miss.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first HEAD X-Cache = %q, want MISS", got)
	}
	hit := head()
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second HEAD X-Cache = %q, want HIT", got)
	}
	if got, want := hit.Header().Get("Content-Length"), miss.Header().Get("Content-Length"); got != want {
		t.Errorf("HEAD hit Content-Length = %q, miss = %q — RFC 9110 §9.3.2 wants what a GET would report", got, want)
	}
	if hit.Body.Len() != 0 {
		t.Errorf("HEAD hit wrote %d body bytes", hit.Body.Len())
	}
}

// The other half of the same rule: GET and HEAD entries are distinct and must
// not answer each other. A HEAD entry has no body to give a GET, and a GET
// entry's body must not be sent in reply to a HEAD.
func TestHeadAndGetDoNotShareAnEntry(t *testing.T) {
	const body = "SECRET-FROM-ORIGIN"
	var heads, gets atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == http.MethodHead {
			heads.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		gets.Add(1)
		io.WriteString(w, body)
	}))
	defer origin.Close()

	h := cachingProxy(t, cache.New(1<<20, 1<<16))
	do := func(method string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, origin.URL+"/a", nil)
		req.RemoteAddr = "10.1.2.3:5000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	do(http.MethodHead)
	// A GET after a HEAD must reach the origin: the HEAD entry has no body.
	get := do(http.MethodGet)
	if get.Body.String() != body {
		t.Errorf("GET after HEAD returned %q, want %q", get.Body.String(), body)
	}
	if gets.Load() != 1 {
		t.Errorf("the origin saw %d GETs, want 1 — a HEAD entry answered a GET", gets.Load())
	}
	// And the GET entry must not answer a HEAD with a body.
	hd := do(http.MethodHead)
	if hd.Body.Len() != 0 {
		t.Errorf("HEAD returned %d body bytes from the GET entry", hd.Body.Len())
	}
}

// PROXY-91. An origin that declares more than it sends leaves the client with a
// truncated body and a correct framing error. The proxy used to record the same
// exchange as a clean 200, served, with nothing in the log at any level.
func TestTruncatedRelayIsVisible(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"+
					strings.Repeat("x", 100))
			}(c)
		}
	}()

	var diag bytes.Buffer
	lg, _ := log.New(log.WithOutput(&diag), log.WithLevel(log.WARN))
	var got server.Exchange
	h := server.AccountingMiddleware(
		NewForward(lg, func(string) map[string]string { return nil }, Policy{AllowPrivate: true}),
		server.Accounting{Completed: func(e server.Exchange) { got = e }})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := proxyClient(t, srv.URL).Get("http://" + ln.Addr().String() + "/a")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr == nil || len(body) != 100 {
		t.Fatalf("expected a truncated read, got %d bytes and err=%v", len(body), readErr)
	}

	// Both surfaces, because an operator looks in one or the other.
	if !got.Incomplete {
		t.Errorf("the access record says the exchange completed: %+v", got)
	}
	if !strings.Contains(diag.String(), "Relay ended early") {
		t.Errorf("nothing was logged about a truncated relay:\n%s", diag.String())
	}
	// The signal has to survive the assembled stack, not just a bare writer —
	// which is how SetServed was lost in PROXY-63.
	if got.Status != http.StatusOK {
		t.Errorf("status = %d; the status is on the wire before the failure and cannot change", got.Status)
	}
}
