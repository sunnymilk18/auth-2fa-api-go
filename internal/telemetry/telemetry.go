// Package telemetry wires up OpenTelemetry metrics and logs: a
// MeterProvider and a LoggerProvider that both export over OTLP/HTTP to a
// collector (see docker-compose.yml's otel-collector service), which in
// turn feeds Prometheus (metrics) and Loki (logs) for Grafana to show.
// No traces yet — see internal/middleware's Metrics for what metrics
// actually get recorded, and SetupLogging below for logs.
package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// SetupMetrics wires the global MeterProvider to export via OTLP/HTTP,
// tagged with serviceName so Grafana can tell this service's metrics
// apart from others sharing the same collector.
//
// endpoint is only used as an on/off switch here — pass
// os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), and leave it unset to disable
// export entirely rather than failing startup (metrics are an optional
// extra, not something that should be able to take the API down if the
// collector isn't reachable).
//
// The actual exporter (otlpmetrichttp.New below) deliberately takes no
// WithEndpoint/WithInsecure options — it reads OTEL_EXPORTER_OTLP_ENDPOINT
// itself, and per the OTel spec that variable is a full URL *with* scheme
// (e.g. "http://otel-collector:4318", not a bare "otel-collector:4318").
// Passing the same bare value again via WithEndpoint on top of that
// doubles it up: the SDK's own env parsing, finding no "://", treats the
// whole value as a path rather than a host, and it ends up appended into
// the request path alongside whatever WithEndpoint sets as the host —
// producing a mangled URL like ".../otel-collector:4318/v1/metrics"
// instead of ".../v1/metrics". The scheme also drives TLS on/off by
// itself (http:// -> insecure, https:// -> TLS) — one more reason not to
// set WithInsecure() explicitly here too. SetupLogging below hits the
// exact same exporter shape and follows the same rule.
func SetupMetrics(ctx context.Context, endpoint, serviceName string) (shutdown func(context.Context) error, err error) {
	noop := func(context.Context) error { return nil }
	if endpoint == "" {
		return noop, nil
	}

	exporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return noop, fmt.Errorf("creating OTLP metric exporter: %w", err)
	}

	res, err := newResource(ctx, serviceName)
	if err != nil {
		return noop, err
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(provider)

	return provider.Shutdown, nil
}

// Meter returns a named Meter off the global MeterProvider — a no-op one
// if SetupMetrics was never called or ran with no endpoint, so callers
// never need to check whether telemetry is actually enabled before using
// it.
func Meter(name string) metric.Meter {
	return otel.Meter(name)
}

func newResource(ctx context.Context, serviceName string) (*resource.Resource, error) {
	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(serviceName)))
	if err != nil {
		return nil, fmt.Errorf("building OTel resource: %w", err)
	}
	return res, nil
}
