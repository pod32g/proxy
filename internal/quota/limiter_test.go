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

func TestHooksReportRejectionsAndBytes(t *testing.T) {
	l, _ := newTestLimiter(t, "client requests 1/s burst 1")
	var scopes []Scope
	var metered int64
	l.Rejected = func(s Scope) { scopes = append(scopes, s) }
	l.Metered = func(n int64) { metered += n }

	l.Allow("10.1.2.3")
	l.Allow("10.1.2.3")
	l.Charge("10.1.2.3", 4096)

	if len(scopes) != 1 || scopes[0] != ScopeClientRequests {
		t.Errorf("scopes = %v, want one client-requests rejection", scopes)
	}
	// Metered counts traffic whether or not a byte quota is configured; it is
	// the number an operator watches to decide whether one is needed.
	if metered != 4096 {
		t.Errorf("metered = %d, want 4096", metered)
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
