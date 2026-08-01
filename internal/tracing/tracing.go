// Package tracing wires OpenTelemetry, when the operator asks for it.
//
// It is the only package that imports an OpenTelemetry SDK. Everything else
// describes what it did through plain function values, so that with tracing off
// there is no tracer to call, no no-op provider to allocate against, and no
// SDK types anywhere on the request path — the hook is nil and the handler
// skips the work entirely.
package tracing

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/otel/sdk/resource"
)

// Tracer is the started tracing pipeline.
type Tracer struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	prop     propagation.TextMapPropagator
}

// Config is what an operator can set.
type Config struct {
	// Endpoint is the OTLP/HTTP collector, e.g. "localhost:4318". Empty means
	// tracing is off.
	Endpoint string
	// Insecure sends over plain HTTP rather than TLS.
	Insecure bool
	// ServiceName identifies this proxy in the trace backend.
	ServiceName string
	// SampleRatio is the fraction of traces recorded, 0 to 1. A proxy sees
	// every request its clients make, so tracing all of them is a decision
	// rather than a default.
	SampleRatio float64
}

// Start builds the pipeline. A zero Endpoint returns (nil, nil): "off" is
// represented by the absence of a tracer, not by a tracer that does nothing, so
// the request path can skip tracing with a nil check.
func Start(ctx context.Context, cfg Config) (*Tracer, error) {
	if cfg.Endpoint == "" {
		return nil, nil
	}
	if cfg.SampleRatio < 0 || cfg.SampleRatio > 1 {
		return nil, fmt.Errorf("sample ratio %v is outside 0..1", cfg.SampleRatio)
	}
	endpoint, err := normalizeEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("building the OTLP exporter: %w", err)
	}

	name := cfg.ServiceName
	if name == "" {
		name = "proxy"
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL, semconv.ServiceName(name),
	))
	if err != nil {
		return nil, fmt.Errorf("building the trace resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		// ParentBased so a client that is already tracing keeps its decision:
		// sampling a child out of a sampled trace produces a gap rather than a
		// saving.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
	)
	prop := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(prop)

	return &Tracer{
		provider: provider,
		tracer:   provider.Tracer("github.com/pod32g/proxy"),
		prop:     prop,
	}, nil
}

// normalizeEndpoint accepts "host:port" or a URL and returns what the OTLP
// exporter wants, which is host:port. Taking only one form would make the flag
// a guessing game.
func normalizeEndpoint(endpoint string) (string, error) {
	if !strings.Contains(endpoint, "://") {
		return endpoint, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid endpoint %q: no host", endpoint)
	}
	return u.Host, nil
}

// Shutdown flushes buffered spans. A batching exporter holds spans in memory,
// so without this the last few seconds of traces are lost on every restart —
// which is exactly the window around a deployment that anyone wants to see.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t == nil || t.provider == nil {
		return nil
	}
	return t.provider.Shutdown(ctx)
}

// Hook returns the function the proxy handler calls to bracket a round trip, or
// nil when tracing is off. Nil is what makes "no cost when disabled" true: the
// handler checks the field and does nothing rather than calling a no-op.
func (t *Tracer) Hook() func(*http.Request, string, string) (*http.Request, func(int, error)) {
	if t == nil {
		return nil
	}
	return t.span
}

// span starts a span for one upstream round trip: it continues the client's
// trace if there is one, and injects W3C traceparent so the origin continues
// ours.
//
// Both halves matter. Without the extract, a client that is already tracing has
// its trace fragmented at this hop — the proxy starts an unrelated trace, and
// the request appears in the backend twice with nothing joining the two, which
// is the exact problem tracing a proxy is meant to solve. Without the inject,
// the trail stops at the origin.
//
// The attributes are the method, the destination host and the path — nothing
// else. The caller passes a path whose query string has already been dropped,
// and url.URL keeps userinfo out of Host, so a credential or a session token
// cannot reach a span from the request line. The only headers read are the
// propagation ones; Authorization, Proxy-Authorization and Cookie are never
// touched and cannot reach the trace.
func (t *Tracer) span(out *http.Request, host, path string) (*http.Request, func(int, error)) {
	// The inbound traceparent survives on the cloned request: it is not
	// hop-by-hop, so the strip that removes Proxy-Authorization leaves it in
	// place, and this is the one spot that has it alongside the outbound request.
	parent := t.prop.Extract(out.Context(), propagation.HeaderCarrier(out.Header))

	ctx, sp := t.tracer.Start(parent, out.Method+" "+host,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(out.Method),
			semconv.ServerAddress(host),
			semconv.URLPath(path),
		),
	)
	out = out.WithContext(ctx)
	t.prop.Inject(ctx, propagation.HeaderCarrier(out.Header))

	return out, func(status int, err error) {
		if status > 0 {
			sp.SetAttributes(semconv.HTTPResponseStatusCode(status))
		}
		if err != nil {
			sp.RecordError(err)
		}
		sp.End()
	}
}

// ShutdownTimeout is how long the flush at exit may take. Long enough for a
// batch to reach a healthy collector, short enough that an unreachable one does
// not hold up the process.
const ShutdownTimeout = 5 * time.Second
