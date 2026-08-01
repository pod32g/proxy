package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The point of the design: however many distinct hosts pass through, the metric
// never grows past N series. A CounterVec labelled by host in the request path
// would have produced 50,000 here — client-controlled and permanent.
func TestDestinationSeriesAreBoundedByConstruction(t *testing.T) {
	stats := NewDomainStats()
	for i := 0; i < 50000; i++ {
		stats.Record(fmt.Sprintf("host-%d.example.com", i))
	}

	reg := prometheus.NewRegistry()
	if err := reg.Register(NewDestinationCollector(stats, 20)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if n := testutil.CollectAndCount(reg, "proxy_destination_requests"); n != 20 {
		t.Errorf("collected %d series, want exactly 20", n)
	}
}

func TestDestinationCollectorReportsTheBusiestHosts(t *testing.T) {
	stats := NewDomainStats()
	for i := 0; i < 5; i++ {
		stats.Record("busy.example.com")
	}
	stats.Record("quiet.example.com")
	for i := 0; i < 3; i++ {
		stats.Record("middling.example.com")
	}

	reg := prometheus.NewRegistry()
	reg.Register(NewDestinationCollector(stats, 2))

	out, err := testutil.GatherAndLint(reg)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, p := range out {
		t.Errorf("lint problem: %s: %s", p.Metric, p.Text)
	}

	var buf strings.Builder
	if err := testutil.CollectAndCompare(
		NewDestinationCollector(stats, 2), strings.NewReader(`
# HELP proxy_destination_requests Requests per destination host, for the busiest hosts only. Sampled from a bounded table: not every host appears, and a host dropped from the table restarts from zero.
# TYPE proxy_destination_requests gauge
proxy_destination_requests{host="busy.example.com"} 5
proxy_destination_requests{host="middling.example.com"} 3
`)); err != nil {
		t.Errorf("%v%s", err, buf.String())
	}
}

// A gauge, not a counter: the underlying table prunes, so the value can fall.
// Declaring it a counter would have Prometheus read every prune as a restart
// and invent a rate spike from it.
func TestDestinationMetricIsAGauge(t *testing.T) {
	stats := NewDomainStats()
	stats.Record("example.com")
	reg := prometheus.NewRegistry()
	reg.Register(NewDestinationCollector(stats, 5))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(families) != 1 {
		t.Fatalf("got %d metric families, want 1", len(families))
	}
	if got := families[0].GetType().String(); got != "GAUGE" {
		t.Errorf("type = %s, want GAUGE", got)
	}
}

func TestDestinationCollectorHandlesNoStats(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.Register(NewDestinationCollector(nil, 5))
	if n := testutil.CollectAndCount(reg, "proxy_destination_requests"); n != 0 {
		t.Errorf("collected %d series from a nil table", n)
	}
}

func TestDestinationCollectorDefaultsTheTop(t *testing.T) {
	stats := NewDomainStats()
	for i := 0; i < 100; i++ {
		stats.Record(fmt.Sprintf("h%d.test", i))
	}
	reg := prometheus.NewRegistry()
	reg.Register(NewDestinationCollector(stats, 0))
	if n := testutil.CollectAndCount(reg, "proxy_destination_requests"); n != DefaultTopDestinations {
		t.Errorf("collected %d series, want the default %d", n, DefaultTopDestinations)
	}
}
