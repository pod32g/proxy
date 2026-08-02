// Package guard turns a panic on a spawned goroutine into a logged error
// rather than a dead process.
//
// net/http recovers a panic in a handler goroutine, so an ordinary request that
// panics costs one connection. Nothing recovers a panic on a goroutine the
// handler spawned, and a proxy spawns several: two per tunnel, one per
// listener, one watching for reloads. A panic on any of them takes the process
// down and every other connection with it.
//
// That asymmetry was the defect. Accounting.Completed — the access log sink,
// the destination counter, the quota release — runs in the handler goroutine
// for an ordinary request and on the tunnel-close goroutine for a hijacked one.
// The same callback, with two very different blast radii, and nothing saying
// so. A panicking sink was reproduced killing the process outright.
//
// This package exists so recovery is one thing every spawned goroutine goes
// through, rather than a defer somebody remembers to add. Recovering is not
// forgiving the bug: the panic and its stack are logged at ERROR, which is what
// makes it findable rather than fatal.
package guard

import (
	"runtime/debug"

	log "github.com/pod32g/simple-logger"
)

// Go runs fn on a new goroutine, surviving a panic in it.
//
// what names the work, so a recovered panic says which goroutine died rather
// than only where. "tunnel", "reload watcher", "listener https".
func Go(logger *log.Logger, what string, fn func()) {
	go Do(logger, what, fn)
}

// Do runs fn on the current goroutine, surviving a panic in it. For work that
// is already on a goroutine of its own.
func Do(logger *log.Logger, what string, fn func()) {
	defer Recover(logger, what)
	fn()
}

// Recover is the deferred half, for callers that need to do something else in
// the same defer. It must be called directly from a defer to see the panic.
//
// The stack is captured here, inside the recovery, so it is the panicking one
// rather than the unwound remains of it — which is what re-panicking would
// have produced, and why this logs rather than re-panics.
func Recover(logger *log.Logger, what string) {
	r := recover()
	if r == nil {
		return
	}
	if logger == nil {
		// Better than losing it entirely: without a logger there is nowhere to
		// put a stack, and swallowing it silently would make a crash into a
		// mystery. The panic is re-raised so it is at least visible.
		panic(r)
	}
	logger.Error("Recovered from a panic; this is a bug",
		log.String("goroutine", what),
		log.String("panic", stringify(r)),
		log.String("stack", string(debug.Stack())))
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case error:
		return t.Error()
	default:
		return "non-error panic value"
	}
}
