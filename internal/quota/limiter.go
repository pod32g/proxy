package quota

import (
	"sync"
	"time"
)

// Scope names what ran out, so a refusal can say which allowance was exhausted
// and metrics can tell a noisy client apart from a saturated proxy.
type Scope string

const (
	ScopeClientRequests Scope = "client-requests"
	ScopeClientBytes    Scope = "client-bytes"
	ScopeGlobalRequests Scope = "global-requests"
	ScopeGlobalBytes    Scope = "global-bytes"
)

// Bound the per-client table the same way the auth-failure table is bounded: a
// spray from many forged sources must not become its own memory-growth problem.
const (
	maxTrackedClients = 20000
	pruneToClients    = 10000
	// A bucket idle for longer than this is refilled to capacity anyway, so
	// dropping it loses nothing.
	idleEviction = 10 * time.Minute
)

// bucket is a token bucket. Tokens are allowed to go negative for byte
// accounting, where the cost is only known after the traffic has flowed.
type bucket struct {
	tokens float64
	last   time.Time
}

// refill brings the bucket up to date against a limit that may have changed
// since the last call.
func (b *bucket) refill(l Limit, now time.Time) {
	capacity := l.capacity()
	if b.last.IsZero() {
		b.tokens = capacity
		b.last = now
		return
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * l.PerSecond
		b.last = now
	}
	if b.tokens > capacity {
		b.tokens = capacity
	}
}

// wait returns how long until the bucket holds n tokens.
func (b *bucket) wait(l Limit, n float64) time.Duration {
	if b.tokens >= n || l.PerSecond <= 0 {
		return 0
	}
	return time.Duration((n - b.tokens) / l.PerSecond * float64(time.Second))
}

// state is one scope's pair of buckets plus its last-use time, for eviction.
type state struct {
	requests bucket
	bytes    bucket
	seen     time.Time
}

// Limiter enforces a Set. The set is read through a function on every request,
// so quotas changed through the UI or API take effect without a restart, the
// same way credentials and policy rules do.
type Limiter struct {
	set func() *Set

	// now is swappable so the tests can drive the clock instead of sleeping.
	now func() time.Time

	mu      sync.Mutex
	global  state
	clients map[string]*state

	// Rejected and Tracked are optional hooks for metrics. Relayed bytes are
	// not reported here: the accounting middleware already splits them by
	// direction for the metrics, and counting them twice from two places is how
	// the two numbers end up disagreeing.
	Rejected func(Scope)
	Tracked  func(n int)
}

// NewLimiter builds a limiter over a set that may change at runtime.
func NewLimiter(set func() *Set) *Limiter {
	if set == nil {
		set = func() *Set { return nil }
	}
	return &Limiter{set: set, now: time.Now, clients: make(map[string]*state)}
}

// Allow admits one request from a client, reporting how long to wait and which
// allowance was exhausted when it refuses.
//
// The byte check is a deficit check, not a reservation: a request is refused
// only when previous traffic has already overdrawn the allowance. See the
// package comment for why a byte ceiling cannot be enforced up front.
func (l *Limiter) Allow(clientIP string) (bool, time.Duration, Scope) {
	set := l.set()
	if set.Empty() {
		return true, 0, ""
	}
	spec := set.For(clientIP)
	global := set.Global

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	client := l.clientState(clientIP, now)

	// Check every scope before spending anything. Taking a client token and
	// then failing the global check would charge for a request that never ran.
	for _, c := range []struct {
		st    *state
		limit Limit
		bytes bool
		scope Scope
	}{
		{client, spec.Requests, false, ScopeClientRequests},
		{client, spec.Bytes, true, ScopeClientBytes},
		{&l.global, global.Requests, false, ScopeGlobalRequests},
		{&l.global, global.Bytes, true, ScopeGlobalBytes},
	} {
		if c.limit.Unlimited() {
			continue
		}
		b := &c.st.requests
		need := float64(1)
		if c.bytes {
			b = &c.st.bytes
			// Overdrawn means "wait until you are back in credit", so the
			// threshold is zero rather than a whole request's worth.
			need = 0
		}
		b.refill(c.limit, now)
		if wait := b.wait(c.limit, need); wait > 0 {
			if l.Rejected != nil {
				l.Rejected(c.scope)
			}
			return false, wait, c.scope
		}
	}

	if !spec.Requests.Unlimited() {
		client.requests.tokens--
	}
	if !global.Requests.Unlimited() {
		l.global.requests.tokens--
	}
	return true, 0, ""
}

// Charge debits bytes already relayed on a client's behalf. It never refuses —
// the traffic has happened — it only makes the next Allow account for it.
func (l *Limiter) Charge(clientIP string, n int64) {
	if n <= 0 {
		return
	}
	set := l.set()
	if set.Empty() {
		return
	}
	spec := set.For(clientIP)
	if spec.Bytes.Unlimited() && set.Global.Bytes.Unlimited() {
		return
	}

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Floor the deficit at one full burst. Without it a single multi-gigabyte
	// download would put a client hours past its allowance, which is a lockout
	// dressed up as a quota.
	debit := func(b *bucket, limit Limit) {
		if limit.Unlimited() {
			return
		}
		b.refill(limit, now)
		b.tokens -= float64(n)
		if floor := -limit.capacity(); b.tokens < floor {
			b.tokens = floor
		}
	}
	debit(&l.clientState(clientIP, now).bytes, spec.Bytes)
	debit(&l.global.bytes, set.Global.Bytes)
}

// clientState returns a client's buckets, creating them on first use. Callers
// hold l.mu.
func (l *Limiter) clientState(clientIP string, now time.Time) *state {
	if l.clients == nil {
		l.clients = make(map[string]*state)
	}
	st, ok := l.clients[clientIP]
	if !ok {
		if len(l.clients) >= maxTrackedClients {
			l.prune(now)
		}
		st = &state{}
		l.clients[clientIP] = st
	}
	st.seen = now
	if l.Tracked != nil {
		l.Tracked(len(l.clients))
	}
	return st
}

// prune drops idle clients, then the oldest, until the table is back under the
// low-water mark. Callers hold l.mu.
func (l *Limiter) prune(now time.Time) {
	for k, st := range l.clients {
		if now.Sub(st.seen) >= idleEviction {
			delete(l.clients, k)
		}
	}
	// Idle eviction alone is not enough under a sustained spray, where every
	// entry is recent. Drop arbitrary entries rather than let the table grow:
	// a dropped bucket refills to full, which is the generous direction, and
	// the global ceiling still holds the line.
	for k := range l.clients {
		if len(l.clients) <= pruneToClients {
			break
		}
		delete(l.clients, k)
	}
}
