package server

import "github.com/prometheus/client_golang/prometheus"

// DefaultTopDestinations is how many hosts the destination collector reports.
// It is the series count, so it is deliberately small.
const DefaultTopDestinations = 20

// destinationCollector exports request counts for the busiest destinations.
//
// The obvious implementation — a CounterVec labelled by host, incremented in
// the request path — is the one that kills a Prometheus. A forward proxy takes
// destinations from untrusted clients, so the label values are chosen by
// whoever is sending traffic: the series count is attacker-controlled, and
// every series ever created stays in memory for the life of the process.
// Capping the number of distinct labels does not fix it either, because the cap
// bounds concurrent values while the churn still creates unbounded series over
// time.
//
// So nothing is labelled per request. This collector reads the top-N from the
// table PROXY-20 already bounded, at scrape time. The result is at most N series
// regardless of traffic — bounded by construction rather than by a limit
// somebody has to remember to enforce — and there is no per-request cost at
// all, only work when Prometheus asks.
//
// The trade-off is honest and worth stating: these counts are the top of a
// pruned table, not an exact accounting. A host that never makes the top N is
// invisible here, and a host that falls out of the table restarts from zero, so
// the counter can go down. Use it to see what the proxy is busiest with, not to
// bill anyone.
type destinationCollector struct {
	stats *DomainStats
	top   int
	desc  *prometheus.Desc
}

// NewDestinationCollector builds the collector. It is registered only when the
// operator asks for it: even N hostnames is information some sites do not want
// in their metrics store, where the retention and the access controls are not
// the ones they chose for their access logs.
func NewDestinationCollector(stats *DomainStats, top int) prometheus.Collector {
	if top <= 0 {
		top = DefaultTopDestinations
	}
	return &destinationCollector{
		stats: stats,
		top:   top,
		desc: prometheus.NewDesc(
			"proxy_destination_requests",
			"Requests per destination host, for the busiest hosts only. "+
				"Sampled from a bounded table: not every host appears, and a host "+
				"dropped from the table restarts from zero.",
			[]string{"host"}, nil,
		),
	}
}

func (c *destinationCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *destinationCollector) Collect(ch chan<- prometheus.Metric) {
	if c.stats == nil {
		return
	}
	// A gauge, not a counter: the underlying table prunes, so the value can go
	// down, and declaring it a counter would have Prometheus treat every prune
	// as a process restart and invent a rate spike out of it.
	for _, s := range c.stats.Top(c.top) {
		ch <- prometheus.MustNewConstMetric(
			c.desc, prometheus.GaugeValue, float64(s.Count), s.Host,
		)
	}
}
