package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pod32g/proxy/internal/config"
	log "github.com/pod32g/simple-logger"
)

// The access log and the quota charge run on every request. PROXY-19 is on
// record as the case where per-request work on this path was the problem, so
// the cost is measured rather than assumed.
//
// The response writer here discards rather than buffering. httptest.NewRecorder
// grows a bytes.Buffer to hold the whole body, and that allocation is an order
// of magnitude larger than anything the middleware does — benchmarking through
// it measures the recorder and calls the result a proxy measurement.

// discardWriter is a ResponseWriter that keeps no data, so the benchmark
// measures the middleware and the handler rather than a growing buffer.
type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header {
	if d.h == nil {
		d.h = make(http.Header)
	}
	return d.h
}
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

func benchHandler(size int) http.Handler {
	body := []byte(strings.Repeat("x", size))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
}

func runBench(b *testing.B, h http.Handler) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/some/path", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	w := &discardWriter{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(w, req)
	}
}

// A 32KB body: one Write, so the per-request fixed cost dominates and is what
// the comparison actually shows.
const benchBody = 32 << 10

func BenchmarkBaselineNoAccounting(b *testing.B) {
	runBench(b, benchHandler(benchBody))
}

// No hooks must be a true passthrough, not a wrapper that counts into nothing.
func BenchmarkAccountingDisabled(b *testing.B) {
	runBench(b, AccountingMiddleware(benchHandler(benchBody), Accounting{}))
}

func BenchmarkAccountingChargeOnly(b *testing.B) {
	runBench(b, AccountingMiddleware(benchHandler(benchBody), Accounting{
		Charge: func(string, int64) {},
	}))
}

func BenchmarkAccessLogStructuredText(b *testing.B) {
	logger, err := config.NewLogger(io.Discard, log.INFO, "text")
	if err != nil {
		b.Fatal(err)
	}
	runBench(b, AccountingMiddleware(benchHandler(benchBody), Accounting{
		Charge:    func(string, int64) {},
		Completed: NewAccessLog("structured", logger, nil),
	}))
}

func BenchmarkAccessLogStructuredJSON(b *testing.B) {
	logger, err := config.NewLogger(io.Discard, log.INFO, "json")
	if err != nil {
		b.Fatal(err)
	}
	runBench(b, AccountingMiddleware(benchHandler(benchBody), Accounting{
		Charge:    func(string, int64) {},
		Completed: NewAccessLog("structured", logger, nil),
	}))
}

func BenchmarkAccessLogCombined(b *testing.B) {
	runBench(b, AccountingMiddleware(benchHandler(benchBody), Accounting{
		Charge:    func(string, int64) {},
		Completed: NewAccessLog("combined", nil, io.Discard),
	}))
}
