package quota

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// clock drives the limiter without sleeping, so the tests assert on the bucket
// arithmetic rather than on how busy the machine is.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(t *testing.T, text string) (*Limiter, *clock) {
	t.Helper()
	set := mustParse(t, text)
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := NewLimiter(func() *Set { return set })
	l.now = c.now
	return l, c
}

func TestUnlimitedByDefault(t *testing.T) {
	l, _ := newTestLimiter(t, "")
	for i := 0; i < 1000; i++ {
		if ok, _, _ := l.Allow("10.1.2.3"); !ok {
			t.Fatalf("refused request %d with no quotas configured", i)
		}
	}
}

func TestRequestQuotaSpendsTheBurstThenRefills(t *testing.T) {
	l, c := newTestLimiter(t, "client requests 10/s burst 20")

	for i := 0; i < 20; i++ {
		if ok, _, _ := l.Allow("10.1.2.3"); !ok {
			t.Fatalf("refused request %d of the 20-request burst", i+1)
		}
	}
	ok, retryAfter, scope := l.Allow("10.1.2.3")
	if ok {
		t.Fatal("21st request was admitted; the burst should be spent")
	}
	if scope != ScopeClientRequests {
		t.Errorf("scope = %q, want %q", scope, ScopeClientRequests)
	}
	// One token at 10/s is 100ms away.
	if retryAfter <= 0 || retryAfter > 200*time.Millisecond {
		t.Errorf("retryAfter = %v, want roughly 100ms", retryAfter)
	}

	c.add(time.Second) // ten tokens back
	for i := 0; i < 10; i++ {
		if ok, _, _ := l.Allow("10.1.2.3"); !ok {
			t.Fatalf("refused request %d after a second of refill", i+1)
		}
	}
	if ok, _, _ := l.Allow("10.1.2.3"); ok {
		t.Error("admitted an 11th request; only a second had passed")
	}
}

func TestQuotasAreKeyedPerClient(t *testing.T) {
	l, _ := newTestLimiter(t, "client requests 1/s burst 1")
	if ok, _, _ := l.Allow("10.1.2.3"); !ok {
		t.Fatal("first client refused")
	}
	if ok, _, _ := l.Allow("10.1.2.3"); ok {
		t.Fatal("first client got a second request")
	}
	// A different client has its own bucket and must not inherit the exhaustion.
	if ok, _, _ := l.Allow("10.1.2.4"); !ok {
		t.Fatal("second client refused on someone else's quota")
	}
}

func TestGlobalCeilingAppliesAcrossClients(t *testing.T) {
	l, _ := newTestLimiter(t, "global requests 5/s burst 5")
	for i := 0; i < 5; i++ {
		if ok, _, _ := l.Allow(fmt.Sprintf("10.0.0.%d", i)); !ok {
			t.Fatalf("refused request %d below the global ceiling", i+1)
		}
	}
	ok, _, scope := l.Allow("10.0.0.99")
	if ok {
		t.Fatal("admitted a request past the global ceiling")
	}
	if scope != ScopeGlobalRequests {
		t.Errorf("scope = %q, want %q", scope, ScopeGlobalRequests)
	}
}

// A client token must not be spent on a request the global ceiling then
// refuses: the request never ran, so charging for it is wrong twice over.
func TestGlobalRefusalDoesNotSpendTheClientToken(t *testing.T) {
	l, _ := newTestLimiter(t, "global requests 1/s burst 1\nclient requests 100/s burst 100")
	if ok, _, _ := l.Allow("10.1.2.3"); !ok {
		t.Fatal("first request refused")
	}
	if ok, _, scope := l.Allow("10.1.2.3"); ok || scope != ScopeGlobalRequests {
		t.Fatalf("want a global refusal, got ok=%v scope=%q", ok, scope)
	}

	before := l.clients["10.1.2.3"].requests.tokens
	l.Allow("10.1.2.3")
	if after := l.clients["10.1.2.3"].requests.tokens; after != before {
		t.Errorf("client tokens moved from %v to %v on a globally refused request", before, after)
	}
}

// The whole point of the byte design: the charge lands after the traffic, and
// the refusal lands on the next request rather than mid-transfer.
func TestByteQuotaRefusesTheNextRequestNotTheCurrentOne(t *testing.T) {
	l, c := newTestLimiter(t, "client bytes 1MB/s burst 1MB")

	if ok, _, _ := l.Allow("10.1.2.3"); !ok {
		t.Fatal("first request refused before any traffic")
	}
	// A 5MB response on a 1MB/s allowance. It completes — nothing is truncated.
	l.Charge("10.1.2.3", 5<<20)

	ok, retryAfter, scope := l.Allow("10.1.2.3")
	if ok {
		t.Fatal("admitted a request while the client was overdrawn")
	}
	if scope != ScopeClientBytes {
		t.Errorf("scope = %q, want %q", scope, ScopeClientBytes)
	}
	// The deficit is floored at one burst, so the wait is one refill window and
	// not the five seconds the raw overspend would imply.
	if retryAfter > 1100*time.Millisecond {
		t.Errorf("retryAfter = %v, want at most one refill window", retryAfter)
	}

	c.add(2 * time.Second)
	if ok, _, _ := l.Allow("10.1.2.3"); !ok {
		t.Error("still refused after the bucket had time to refill")
	}
}

func TestByteDeficitIsFlooredAtOneBurst(t *testing.T) {
	l, _ := newTestLimiter(t, "client bytes 1MiB/s burst 2MiB")
	l.Charge("10.1.2.3", 500<<20) // half a gigabyte
	if got := l.clients["10.1.2.3"].bytes.tokens; got != -(2 << 20) {
		t.Errorf("tokens = %v, want the floor of -2MiB", got)
	}
}

func TestGlobalByteQuota(t *testing.T) {
	l, _ := newTestLimiter(t, "global bytes 1MB/s burst 1MB")
	l.Charge("10.1.2.3", 4<<20)
	// Charged against one client, but the ceiling is shared, so another client
	// feels it too.
	if ok, _, scope := l.Allow("10.9.9.9"); ok || scope != ScopeGlobalBytes {
		t.Errorf("want a global byte refusal, got ok=%v scope=%q", ok, scope)
	}
}

func TestChargeIgnoresNonPositive(t *testing.T) {
	l, _ := newTestLimiter(t, "client bytes 1MB/s")
	l.Charge("10.1.2.3", 0)
	l.Charge("10.1.2.3", -5)
	if ok, _, _ := l.Allow("10.1.2.3"); !ok {
		t.Error("a zero-byte charge should not overdraw anything")
	}
}

func TestRejectionsAreReported(t *testing.T) {
	l, _ := newTestLimiter(t, "client requests 1/s burst 1")
	var scopes []Scope
	l.Rejected = func(s Scope) { scopes = append(scopes, s) }

	l.Allow("10.1.2.3")
	l.Allow("10.1.2.3")

	if len(scopes) != 1 || scopes[0] != ScopeClientRequests {
		t.Errorf("scopes = %v, want one client-requests rejection", scopes)
	}
}

func TestQuotaChangesTakeEffectWithoutRestart(t *testing.T) {
	set := mustParse(t, "")
	var mu sync.Mutex
	l := NewLimiter(func() *Set {
		mu.Lock()
		defer mu.Unlock()
		return set
	})
	if ok, _, _ := l.Allow("10.1.2.3"); !ok {
		t.Fatal("refused with no quotas")
	}
	mu.Lock()
	set = mustParse(t, "client requests 1/s burst 1")
	mu.Unlock()

	if ok, _, _ := l.Allow("10.1.2.3"); !ok {
		t.Fatal("refused the first request under the new quota")
	}
	if ok, _, _ := l.Allow("10.1.2.3"); ok {
		t.Error("the new quota was not applied to a live limiter")
	}
}

func TestClientTableIsBounded(t *testing.T) {
	l, _ := newTestLimiter(t, "client requests 1000/s")
	for i := 0; i < maxTrackedClients+5000; i++ {
		l.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if n := len(l.clients); n > maxTrackedClients {
		t.Errorf("tracking %d clients, want at most %d", n, maxTrackedClients)
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	l, _ := newTestLimiter(t, "global requests 100000/s burst 100000\nclient bytes 10MB/s")
	l.now = time.Now // real clock: the fake one is not safe to share

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", i%3)
			for j := 0; j < 200; j++ {
				l.Allow(ip)
				l.Charge(ip, 1024)
			}
		}(i)
	}
	wg.Wait()
}

// PROXY-72. A quota below one per second used to refuse every request, forever.
//
// The default burst was "one second of refill", which for any sub-1/s rate is
// less than one whole token — and admission needs one. The bucket was capped at
// that, so it could never fill enough to admit anything. `requests 100/h` did
// not throttle a client to a hundred an hour; it locked them out permanently,
// which is the opposite of what it reads as.
//
// The rates below straddle the boundary in both units. 60/m worked before only
// because it lands on exactly 1.0.
func TestSubSecondRequestQuotasAdmitRequests(t *testing.T) {
	for _, rule := range []string{
		"client requests 100/h",
		"client requests 1/h",
		"client requests 30/m",
		"client requests 59/m",
		"client requests 60/m",
		"client requests 1/s",
		"global requests 100/h",
	} {
		t.Run(rule, func(t *testing.T) {
			l, c := newTestLimiter(t, rule)
			ok, wait, scope := l.Allow("10.0.0.1")
			if !ok {
				t.Fatalf("%q refused the first request (wait %v, scope %q)", rule, wait, scope)
			}

			// And the refusal that follows has to be truthful: the Router puts
			// this straight into Retry-After, so a wait after which the request
			// still fails is a client retrying forever.
			ok, wait, _ = l.Allow("10.0.0.1")
			if ok {
				return // a rate fast enough to admit two in the same instant
			}
			if wait <= 0 {
				t.Fatalf("%q refused but reported no wait", rule)
			}
			c.add(wait)
			if ok, wait, scope := l.Allow("10.0.0.1"); !ok {
				t.Errorf("%q still refused after the wait it asked for (another %v, scope %q)", rule, wait, scope)
			}
		})
	}
}

// The other direction: the floor must not turn a quota off. A sub-1/s rate
// still has to throttle, not merely stop locking people out.
func TestSubSecondRequestQuotasStillThrottle(t *testing.T) {
	l, c := newTestLimiter(t, "client requests 100/h")
	if ok, _, _ := l.Allow("10.0.0.1"); !ok {
		t.Fatal("the first request was refused")
	}
	if ok, _, _ := l.Allow("10.0.0.1"); ok {
		t.Error("a second immediate request was admitted; 100/h should not burst")
	}
	// A hundred an hour is one every thirty-six seconds.
	c.add(35 * time.Second)
	if ok, _, _ := l.Allow("10.0.0.1"); ok {
		t.Error("admitted after 35s; 100/h is one every 36s")
	}
	c.add(2 * time.Second)
	if ok, _, _ := l.Allow("10.0.0.1"); !ok {
		t.Error("still refused after 37s; 100/h is one every 36s")
	}
}
