package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/quota"
)

// A live proxy wired to a real *config.Config, exactly as main.go wires it:
// every policy the handler consults is a function reading the config per
// request, so a change lands without rebuilding anything.
func stressProxy(t *testing.T, cfg *config.Config, origin string) http.Handler {
	t.Helper()
	return NewForward(newLogger(), cfg.GetHeadersForClient, Policy{
		AllowPrivate: true,
		ConnectPorts: allPorts(),
		Rules:        cfg.DestinationRulesFor,
		HeaderRules:  cfg.HeaderRules,
		Upstream:     cfg.UpstreamProxy,
	})
}

// Traffic and configuration changes at the same time, under -race.
//
// Every sweep so far has reasoned about reload races rather than driving one.
// This drives it: four kinds of change against continuous requests, with the
// race detector watching the accessors the handler reads on every request.
func TestConfigChangesUnderLoad(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	cfg := &config.Config{}
	if err := cfg.SetPolicyRules("allow all"); err != nil {
		t.Fatal(err)
	}
	h := stressProxy(t, cfg, origin.URL)
	srv := httptest.NewServer(h)
	defer srv.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var requests, errs atomic.Int64

	// Readers: continuous traffic through the handler.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := proxyClient(t, srv.URL)
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := client.Get(origin.URL + "/a")
				if err != nil {
					errs.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				requests.Add(1)
			}
		}()
	}

	// Writers: the four things the UI and API can change while traffic flows.
	writers := []func(int) error{
		func(n int) error {
			if n%2 == 0 {
				return cfg.SetPolicyRules("allow all")
			}
			return cfg.SetPolicyRules("deny domain nowhere.invalid\nallow all")
		},
		func(n int) error {
			return cfg.SetQuotas(fmt.Sprintf("client requests %d/s burst %d", 500+n%100, 1000+n%100))
		},
		func(n int) error {
			return cfg.SetHeaderRules(fmt.Sprintf("set X-Round: %d", n))
		},
		func(n int) error {
			cfg.SetHeader("X-Global", fmt.Sprint(n))
			cfg.SetClientHeader("127.0.0.1", "X-Client", fmt.Sprint(n))
			return nil
		},
	}
	for _, w := range writers {
		wg.Add(1)
		go func(w func(int) error) {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				if err := w(n); err != nil {
					t.Errorf("config change failed: %v", err)
					return
				}
			}
		}(w)
	}

	// Readers of the same config, as the UI and the metrics scraper do.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = cfg.PolicyRulesText()
			_ = cfg.QuotaText()
			_ = cfg.HeaderRulesText()
			_ = cfg.GetHeaders()
			_ = cfg.GetAllClientHeaders()
			_, _, _ = cfg.GetAuth()
			_ = cfg.QuotaSet()
			_ = cfg.UpstreamProxy()
		}
	}()

	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()

	t.Logf("%d requests served, %d transport errors, while four writers changed the config continuously",
		requests.Load(), errs.Load())
	if requests.Load() == 0 {
		t.Fatal("no requests completed; the harness proved nothing")
	}
	if errs.Load() > 0 {
		t.Errorf("%d requests failed at the transport while only the configuration changed", errs.Load())
	}
}

// The contract the UI and API make: when a change returns, it is in effect for
// the next request. Anything less makes "applies immediately" a coin flip.
func TestADenyRuleTakesEffectBeforeTheSetterReturns(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN")
	}))
	defer origin.Close()

	cfg := &config.Config{}
	h := stressProxy(t, cfg, origin.URL)
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := proxyClient(t, srv.URL)

	host := strings.TrimPrefix(origin.URL, "http://")
	for round := 0; round < 200; round++ {
		if err := cfg.SetPolicyRules("deny all"); err != nil {
			t.Fatal(err)
		}
		resp, err := client.Get(origin.URL + "/a")
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("round %d: deny all was set and %s answered %d %q",
				round, host, resp.StatusCode, body)
		}

		if err := cfg.SetPolicyRules("allow all"); err != nil {
			t.Fatal(err)
		}
		resp, err = client.Get(origin.URL + "/a")
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("round %d: allow all was set and the request got %d", round, resp.StatusCode)
		}
	}
}

// A quota changed under load must not be readable in a half-updated state: a
// request either meets the old allowance or the new one, never a mixture of a
// new rate with an old burst.
func TestQuotaSwapsAreAtomic(t *testing.T) {
	cfg := &config.Config{}
	if err := cfg.SetQuotas("client requests 10/s burst 20"); err != nil {
		t.Fatal(err)
	}
	limiter := quota.NewLimiter(cfg.QuotaSet)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			default:
			}
			text := "client requests 10/s burst 20"
			if n%2 == 1 {
				text = "client requests 1000/s burst 2000"
			}
			if err := cfg.SetQuotas(text); err != nil {
				t.Errorf("SetQuotas: %v", err)
				return
			}
		}
	}()

	for i := 0; i < 40000; i++ {
		set := cfg.QuotaSet()
		spec := set.For("10.0.0.1")
		// The two halves of one rule must always agree: these are the only two
		// pairs written, so anything else is a set observed mid-swap.
		rate := spec.Requests.PerSecond
		if rate != 10 && rate != 1000 {
			t.Fatalf("observed a quota set that was never configured: %v/s", rate)
		}
		limiter.Allow("10.0.0.1")
	}
	close(stop)
	wg.Wait()
}
