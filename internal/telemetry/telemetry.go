// Package telemetry wires up OpenTelemetry metrics: a MeterProvider that
// exports over OTLP/HTTP to a collector (see docker-compose.yml's
// otel-collector service), which in turn feeds Prometheus for Grafana to
// chart. Deliberately metrics-only for now — no traces/logs — see
// internal/middleware's Metrics for what actually gets recorded.
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

// Setup wires the global MeterProvider to export via OTLP/HTTP to endpoint
// (host:port — no scheme, matches otlpmetrichttp.WithEndpoint), tagged with
// serviceName so Grafana can tell this service's metrics apart from
// others sharing the same collector.
//
// endpoint == "" (OTEL_EXPORTER_OTLP_ENDPOINT unset) disables export
// entirely rather than failing startup — metrics are an optional extra,
// not something that should be able to take the API down if the collector
// isn't reachable. Call the returned shutdown func during graceful
// shutdown to flush any metrics still buffered.
func Setup(ctx context.Context, endpoint, serviceName string) (shutdown func(context.Context) error, err error) {
	noop := func(context.Context) error { return nil }
	if endpoint == "" {
		return noop, nil
	}

	exporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(endpoint),
		// The collector in docker-compose.yml has no TLS in front of it —
		// this is traffic between containers on the same private network,
		// not going out to the internet.
		otlpmetrichttp.WithInsecure(),
	)
	if err != nil {
		return noop, fmt.Errorf("creating OTLP metric exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		return noop, fmt.Errorf("building OTel resource: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(provider)

	return provider.Shutdown, nil
}

// Meter returns a named Meter off the global MeterProvider — a no-op one
// if Setup was never called or ran with no endpoint, so callers never need
// to check whether telemetry is actually enabled before using it.
func Meter(name string) metric.Meter {
	return otel.Meter(name)
}
