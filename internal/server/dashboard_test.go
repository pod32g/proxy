package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// A dashboard that queries a metric nobody exports renders an empty panel, and
// an empty panel reads as "the proxy is idle" rather than "this query is wrong".
// That failure is silent in production and free to catch here, so the committed
// dashboard is checked against the metrics the code actually registers.
func TestDashboardQueriesOnlyExportedMetrics(t *testing.T) {
	path := filepath.Join("..", "..", "grafana", "dashboards", "proxy.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}

	var dash struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}

	exported := exportedMetricNames(t)

	// Histograms are exported as _bucket/_sum/_count; a dashboard legitimately
	// queries those suffixes.
	suffixes := []string{"_bucket", "_sum", "_count", "_total"}
	metricRef := regexp.MustCompile(`proxy_[a-z0-9_]+`)

	var queried int
	for _, panel := range dash.Panels {
		for _, target := range panel.Targets {
			for _, name := range metricRef.FindAllString(target.Expr, -1) {
				queried++
				if exported[name] {
					continue
				}
				trimmed := name
				for _, s := range suffixes {
					if base, ok := strings.CutSuffix(name, s); ok && exported[base] {
						trimmed = base
						break
					}
				}
				if !exported[trimmed] {
					t.Errorf("panel %q queries %q, which nothing exports.\nExported: %v",
						panel.Title, name, sortedKeys(exported))
				}
			}
		}
	}
	if queried == 0 {
		t.Error("no metric references found; the dashboard parser is probably wrong")
	}
}

// fqName pulls the metric name out of a Desc. There is no exported accessor,
// and the String form is stable and documented enough for a test.
var fqName = regexp.MustCompile(`fqName: "([^"]+)"`)

// exportedMetricNames lists every name the proxy declares, including the
// optional destination collector.
//
// Describe rather than Gather: a CounterVec with no observations yet exports no
// families at all, so gathering a freshly built registry reports almost nothing
// and the check would pass by being blind.
func exportedMetricNames(t *testing.T) map[string]bool {
	t.Helper()
	m, err := NewMetrics(prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	collectors := []prometheus.Collector{
		m.Requests, m.Duration, m.Clients, m.AuthFailures,
		m.QuotaRejected, m.RelayedBytes, m.QuotaClients,
		m.UpstreamDuration, m.ActiveTunnels, m.PolicyDecisions,
		NewDestinationCollector(NewDomainStats(), 5),
	}

	out := make(map[string]bool, len(collectors))
	for _, c := range collectors {
		ch := make(chan *prometheus.Desc, 16)
		go func(c prometheus.Collector) {
			c.Describe(ch)
			close(ch)
		}(c)
		for desc := range ch {
			if match := fqName.FindStringSubmatch(desc.String()); match != nil {
				out[match[1]] = true
			}
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The four metrics that predate this dashboard are a compatibility surface:
// anything already alerting on them keeps working only if the names do not move.
func TestOriginalMetricNamesAreStable(t *testing.T) {
	exported := exportedMetricNames(t)
	for _, name := range []string{
		"proxy_http_requests_total",
		"proxy_http_request_duration_seconds",
		"proxy_active_clients",
		"proxy_auth_failures_total",
	} {
		if !exported[name] {
			t.Errorf("%s is no longer exported; existing alerts and dashboards depend on it", name)
		}
	}
}
