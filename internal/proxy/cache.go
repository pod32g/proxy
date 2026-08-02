package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/pod32g/proxy/internal/cache"
)

// serveFromCache answers a request from the cache when it can, and reports
// whether it did.
//
// Returns the stored entry when the request is cacheable but the entry is
// stale, so the caller can revalidate rather than refetch — that is the whole
// economy of a validator.
func serveFromCache(w http.ResponseWriter, r *http.Request, c *cache.Scope) (served bool, stale *cache.Entry) {
	if c == nil {
		return false, nil
	}
	if reason := cache.StorableRequest(r); reason != cache.ReasonStorable {
		// Not cacheable in either direction: a request that identifies a user
		// must neither be served from the cache nor stored in it.
		return false, nil
	}

	entry := c.Get(r)
	if entry == nil {
		c.Miss()
		return false, nil
	}
	// A client asking for no-cache wants the entity confirmed current, not
	// whatever the proxy happens to hold — so it takes the revalidation path
	// even against an entry that is otherwise fresh.
	if !entry.Fresh(time.Now()) || cache.RequestWantsRevalidation(r) {
		return false, entry
	}
	return true, entry
}

// writeEntry replays a stored response.
//
// The stored headers are copied out rather than served in place, which is what
// lets response header rules apply to a hit exactly as they do to a miss — the
// stored entry stays the origin's own, and the rules run on the way out. A hit
// and a miss are indistinguishable to the client, which is the property that
// makes turning the cache on safe.
func writeEntry(w http.ResponseWriter, e *cache.Entry, status string, rewrite func(http.Header)) {
	for name, values := range e.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	// Applied to the copy, before anything is written — a rule that ran after
	// WriteHeader would have no effect at all, which is the quiet kind of
	// wrong.
	if rewrite != nil {
		rewrite(w.Header())
	}
	// So a client — or an operator with curl — can tell a hit from a fetch.
	// Without it the cache is invisible from outside and the only way to know
	// whether it worked is to watch the origin.
	w.Header().Set("X-Cache", status)
	// RFC 9111 §5.1. Set after the rules, not before, because this is a
	// measurement rather than a preference: a rule that could overwrite it
	// would be misreporting the age of the content to everyone downstream, and
	// a downstream cache would extend the lifetime on the strength of it.
	w.Header().Set("Age", strconv.FormatInt(int64(e.Age(time.Now()).Seconds()), 10))
	w.Header().Set("Content-Length", strconv.Itoa(len(e.Body)))
	w.WriteHeader(e.Status)
	_, _ = w.Write(e.Body)
}

// conditional adds validators to a request so the origin can answer 304.
func conditional(out *http.Request, entry *cache.Entry) {
	if entry == nil {
		return
	}
	if entry.ETag != "" {
		out.Header.Set("If-None-Match", entry.ETag)
	}
	if entry.LastModified != "" {
		out.Header.Set("If-Modified-Since", entry.LastModified)
	}
}

// storeResponse buffers and stores a response when it is cacheable, returning
// the body to send onward.
//
// The body is read here rather than streamed because a stored response has to
// be complete. The size limit is checked as it is read: buffering a large body
// only to decide not to store it would be the worst of both outcomes, so
// reading stops at the limit and the remainder streams straight through.
func storeResponse(r *http.Request, resp *http.Response, c *cache.Scope) io.Reader {
	if c == nil {
		return resp.Body
	}
	if cache.StorableRequest(r) != cache.ReasonStorable {
		return resp.Body
	}
	now := time.Now()
	if cache.StorableResponse(resp, now) != cache.ReasonStorable {
		return resp.Body
	}
	ttl, ok := cache.TTL(resp, now)
	if !ok {
		return resp.Body
	}

	limit := c.MaxEntryBytes()
	buf := &bytes.Buffer{}
	// One byte past the limit is enough to know it does not fit, and stops the
	// proxy holding a gigabyte it was never going to keep.
	n, err := io.CopyN(buf, resp.Body, limit+1)
	if err != nil && err != io.EOF {
		// A read error mid-body: hand back what there is and store nothing. The
		// caller's copy will surface the failure to the client.
		return io.MultiReader(buf, resp.Body)
	}
	if n > limit {
		return io.MultiReader(buf, resp.Body)
	}

	body := buf.Bytes()
	c.Store(r, resp, body, ttl)
	return bytes.NewReader(body)
}
