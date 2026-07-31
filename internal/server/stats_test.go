package server

import (
	"fmt"
	"testing"
	"time"
)

func TestDomainStats(t *testing.T) {
	ds := NewDomainStats()
	ds.Record("example.com")
	ds.Record("example.com")
	ds.Record("example.org")
	top := ds.Top(2)
	if len(top) != 2 {
		t.Fatalf("expected 2 results, got %d", len(top))
	}
	if top[0].Host != "example.com" || top[0].Count != 2 {
		t.Fatalf("unexpected top result: %+v", top[0])
	}
}

// Record used to sort the whole table on every request, so cost grew with the
// number of distinct hosts ever seen. With no subscriber there is nothing to
// compute at all.
func TestRecordDoesNotSortWithoutSubscribers(t *testing.T) {
	d := NewDomainStats()
	for i := 0; i < 50000; i++ {
		d.Record(fmt.Sprintf("host-%d.example", i))
	}
	start := time.Now()
	for i := 0; i < 2000; i++ {
		d.Record("hot.example")
	}
	per := time.Since(start) / 2000
	if per > 20*time.Microsecond {
		t.Errorf("Record() costs %v with a large table; it should not be sorting", per)
	}
}

// The table is keyed by hostnames the client picks, so it needs a ceiling.
func TestStatsAreBounded(t *testing.T) {
	d := NewDomainStats()
	for i := 0; i < maxTrackedHosts*2; i++ {
		d.Record(fmt.Sprintf("host-%d.example", i))
	}
	if got := len(d.Top(0)); got > maxTrackedHosts {
		t.Errorf("retained %d hosts, want at most %d", got, maxTrackedHosts)
	}
	if !d.Approximate() {
		t.Error("pruning happened but the table is not reported as approximate")
	}
	// Pruning must keep the hosts that actually matter.
	d2 := NewDomainStats()
	for i := 0; i < 200; i++ {
		d2.Record("popular.example")
	}
	for i := 0; i < maxTrackedHosts*2; i++ {
		d2.Record(fmt.Sprintf("host-%d.example", i))
	}
	top := d2.Top(1)
	if len(top) != 1 || top[0].Host != "popular.example" {
		t.Errorf("pruning dropped the busiest host: %v", top)
	}
}

func TestHostOnly(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"}, // bare IPv6: the old LastIndex split mangled this
		{"", ""},
	} {
		if got := hostOnly(tc.in); got != tc.want {
			t.Errorf("hostOnly(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
