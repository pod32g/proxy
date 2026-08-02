package cache

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Lookup cost must not grow with occupancy. It used to: candidate variant keys
// were found by scanning every entry, under the cache mutex, so a lookup cost
// 51us at ten thousand entries and serialised every other cache operation
// behind it. The cache got slower exactly as it became more useful.
func benchGetAt(b *testing.B, entries int) {
	c := New(1<<30, 1<<20)
	body := make([]byte, 256)
	for i := 0; i < entries; i++ {
		r, _ := http.NewRequest("GET", fmt.Sprintf("http://example.com/%d", i), nil)
		c.Store(r, &http.Response{StatusCode: 200, Header: http.Header{
			"Cache-Control": {"max-age=600"}}}, body, 10*time.Minute)
	}
	r, _ := http.NewRequest("GET", "http://example.com/0", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(r)
	}
}

func BenchmarkCacheGet100(b *testing.B)   { benchGetAt(b, 100) }
func BenchmarkCacheGet1000(b *testing.B)  { benchGetAt(b, 1000) }
func BenchmarkCacheGet10000(b *testing.B) { benchGetAt(b, 10000) }
