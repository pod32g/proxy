package server

import "testing"

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
