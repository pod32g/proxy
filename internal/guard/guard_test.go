package guard

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/pod32g/simple-logger"
)

// safeBuffer is a bytes.Buffer a test can read while a guarded goroutine
// writes to it. bytes.Buffer is not safe for that, and the whole point here is
// to observe another goroutine.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *safeBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func newLogger(t *testing.T) (*log.Logger, *safeBuffer) {
	t.Helper()
	buf := &safeBuffer{}
	lg, err := log.New(log.WithOutput(buf), log.WithLevel(log.DEBUG))
	if err != nil {
		t.Fatal(err)
	}
	return lg, buf
}

// PROXY-95. A panic on a spawned goroutine used to take the process down. This
// test running to completion is the assertion: an unguarded panic here would
// abort the test binary rather than fail a case.
func TestGoSurvivesAPanic(t *testing.T) {
	lg, buf := newLogger(t)
	Go(lg, "tunnel", func() { panic("a sink that panics") })

	// Polled rather than signalled from inside fn: a defer in fn runs during
	// the unwind, before Do's own deferred recovery, so waiting on it would
	// race the logging it is waiting for. Found by writing it the other way.
	deadline := time.Now().Add(3 * time.Second)
	for buf.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	out := buf.String()
	for _, want := range []string{"Recovered from a panic", "tunnel", "a sink that panics", "stack"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log does not mention %q:\n%s", want, out)
		}
	}
}

func TestDoSurvivesAPanicAndNamesTheWork(t *testing.T) {
	lg, buf := newLogger(t)
	Do(lg, "reload watcher", func() { panic(errors.New("bad value")) })
	out := buf.String()
	if !strings.Contains(out, "reload watcher") {
		t.Errorf("the log does not name the goroutine:\n%s", out)
	}
	if !strings.Contains(out, "bad value") {
		t.Errorf("the log does not carry the panic value:\n%s", out)
	}
}

// The stack has to be the panicking one, not the unwound remains of it —
// which is what re-panicking would have produced, and the reason this logs.
func TestTheStackPointsAtThePanic(t *testing.T) {
	lg, buf := newLogger(t)
	Do(lg, "x", func() { theFunctionThatPanics() })
	if !strings.Contains(buf.String(), "theFunctionThatPanics") {
		t.Errorf("the stack does not reach the panicking frame:\n%s", buf.String())
	}
}

func theFunctionThatPanics() { panic("here") }

// Work that does not panic is untouched, and nothing is logged.
func TestNoPanicIsSilent(t *testing.T) {
	lg, buf := newLogger(t)
	ran := false
	Do(lg, "x", func() { ran = true })
	if !ran {
		t.Error("the work did not run")
	}
	if buf.Len() != 0 {
		t.Errorf("a clean run logged something:\n%s", buf.String())
	}
}

// Without a logger there is nowhere to put a stack, and swallowing it would
// turn a crash into a mystery. It is re-raised instead.
func TestNoLoggerRaisesRatherThanSwallows(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a panic with no logger was swallowed silently")
		}
	}()
	Do(nil, "x", func() { panic("boom") })
}
