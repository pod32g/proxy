package api

import (
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/log"
	"github.com/pact-foundation/pact-go/v2/matchers"
	"github.com/pact-foundation/pact-go/v2/version"
)

func TestHeadersContract(t *testing.T) {
	version.CheckVersion()
	log.SetLogLevel("INFO")

	pact, err := consumer.NewV3Pact(consumer.MockHTTPProviderConfig{
		Consumer: "proxy-consumer",
		Provider: "proxy-api",
		PactDir:  filepath.ToSlash(filepath.Join("..", "..", "pacts")),
	})
	if err != nil {
		t.Fatal(err)
	}

	err = pact.
		AddInteraction().
		Given("no headers configured").
		UponReceiving("get headers").
		WithRequest(http.MethodGet, "/headers").
		WillRespondWith(200, func(b *consumer.V3ResponseBuilder) {
			b.Header("Content-Type", matchers.S("application/json")).
				JSONBody(map[string]interface{}{
					"global":  map[string]string{},
					"clients": map[string]interface{}{},
				})
		}).
		ExecuteTest(t, func(cfg consumer.MockServerConfig) error {
			url := fmt.Sprintf("http://%s:%d/headers", cfg.Host, cfg.Port)
			resp, err := http.Get(url)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("status %d", resp.StatusCode)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}
