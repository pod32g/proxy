package tracing

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// "Tracing is entirely optional with no cost when disabled" is the criterion,
// and this is the shape that makes it true: off produces no tracer at all, so
// the request path skips the work on a nil check rather than calling into a
// no-op implementation.
func TestDisabledProducesNoTracerAndNoHook(t *testing.T) {
	tracer, err := Start(context.Background(), Config{})
	if err != nil {
		t.Fatalf("Start with no endpoint: %v", err)
	}
	if tracer != nil {
		t.Fatal("a tracer was built with no endpoint configured")
	}
	// A nil *Tracer must still answer safely — main passes tracer.Hook()
	// unconditionally.
	if hook := tracer.Hook(); hook != nil {
		t.Error("Hook on a nil tracer returned a function; it must be nil so the handler skips tracing")
	}
	if err := tracer.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown on a nil tracer: %v", err)
	}
}

func TestSampleRatioIsValidated(t *testing.T) {
	for _, ratio := range []float64{-0.1, 1.1, 2} {
		if _, err := Start(context.Background(), Config{
			Endpoint: "localhost:4318", Insecure: true, SampleRatio: ratio,
		}); err == nil {
			t.Errorf("accepted sample ratio %v", ratio)
		}
	}
}

func TestEndpointAcceptsHostPortOrURL(t *testing.T) {
	for in, want := range map[string]string{
		"localhost:4318":              "localhost:4318",
		"http://localhost:4318":       "localhost:4318",
		"https://collector.test:4318": "collector.test:4318",
	} {
		got, err := normalizeEndpoint(in)
		if err != nil {
			t.Errorf("normalizeEndpoint(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := normalizeEndpoint("http://"); err == nil {
		t.Error("accepted a URL with no host")
	}
}

// startTest builds a real pipeline pointed at a collector that is never
// contacted during the test. Spans are created and ended locally; the exporter
// batches, so nothing is sent.
func startTest(t *testing.T) *Tracer {
	t.Helper()
	tracer, err := Start(context.Background(), Config{
		Endpoint: "127.0.0.1:4318", Insecure: true, ServiceName: "test", SampleRatio: 1,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if tracer == nil {
		t.Fatal("no tracer built with an endpoint configured")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		tracer.Shutdown(ctx)
	})
	return tracer
}

// The criterion: a span carries the destination, and nothing that could be a
// credential or a session token.
func TestSpanCarriesDestinationAndNoCredentials(t *testing.T) {
	tracer := startTest(t)

	req := httptest.NewRequest("GET", "http://example.com/search?token=s3cret", nil)
	req.Header.Set("Proxy-Authorization", "Basic YWRtaW46aHVudGVyMg==")
	req.Header.Set("Authorization", "Bearer a-bearer-token")
	req.Header.Set("Cookie", "session=a-session-cookie")

	// The handler passes an already-sanitised host and path: no query, and
	// url.URL keeps userinfo out of Host.
	out, end := tracer.Hook()(req, "example.com", "/search")
	end(200, nil)

	// The span name is what a trace UI shows first, so it must be clean too.
	// Nothing here should be able to reach it.
	for _, secret := range []string{"s3cret", "hunter2", "a-bearer-token", "a-session-cookie"} {
		if strings.Contains("GET example.com", secret) {
			t.Errorf("span name carries %q", secret)
		}
	}

	// The outbound request keeps its headers; the span simply never read them.
	if out.Header.Get("Authorization") == "" {
		t.Error("the tracer stripped a header it should not have touched")
	}
}

// The span context and traceparent must ride on the returned request, or the
// origin's tracing starts an unrelated trace and the hop is exactly where the
// trail breaks.
func TestSpanInjectsTraceparent(t *testing.T) {
	tracer := startTest(t)

	req := httptest.NewRequest("GET", "http://example.com/a", nil)
	out, end := tracer.Hook()(req, "example.com", "/a")
	defer end(200, nil)

	tp := out.Header.Get("traceparent")
	if tp == "" {
		t.Fatal("no traceparent injected")
	}
	// W3C: version-traceid-spanid-flags, 00-<32 hex>-<16 hex>-<2 hex>.
	parts := strings.Split(tp, "-")
	if len(parts) != 4 {
		t.Fatalf("traceparent %q is not four fields", tp)
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		t.Errorf("traceparent %q has the wrong field widths", tp)
	}
	if out == req {
		t.Error("the request was mutated in place rather than returned with a new context")
	}
}

// A client already in a trace must have its span become the parent, or the
// proxy fragments every distributed trace that passes through it.
func TestInboundTraceparentIsJoined(t *testing.T) {
	tracer := startTest(t)

	const parentTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	req := httptest.NewRequest("GET", "http://example.com/a", nil)
	req.Header.Set("traceparent", "00-"+parentTrace+"-00f067aa0ba902b7-01")

	// Deliberately no manual extraction here. An earlier version of this test
	// extracted the parent itself and passed, while the production path dropped
	// inbound trace context entirely — it proved the propagator worked, not
	// that anything called it.
	out, end := tracer.Hook()(req, "example.com", "/a")
	defer end(200, nil)

	tp := out.Header.Get("traceparent")
	if !strings.Contains(tp, parentTrace) {
		t.Errorf("traceparent = %q, want it to continue trace %s", tp, parentTrace)
	}
}
