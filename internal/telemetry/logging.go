package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// SetupLogging returns a *slog.Logger that always writes structured JSON
// to stdout (so `docker logs` / Dokploy's log viewer keep working exactly
// as before — nothing about that changes) and, when endpoint is set, ALSO
// ships every record over OTLP to the collector for Loki, same on/off
// switch and endpoint-format rules as SetupMetrics (see its doc comment —
// full URL with scheme, e.g. "http://otel-collector:4318").
//
// Call the returned shutdown func during graceful shutdown to flush any
// log records still buffered — logs already went to stdout synchronously,
// so a missed flush only loses the OTLP copy, never the local one.
func SetupLogging(ctx context.Context, endpoint, serviceName string) (logger *slog.Logger, shutdown func(context.Context) error, err error) {
	noop := func(context.Context) error { return nil }
	stdoutHandler := slog.NewJSONHandler(os.Stdout, nil)

	if endpoint == "" {
		return slog.New(stdoutHandler), noop, nil
	}

	exporter, err := otlploghttp.New(ctx)
	if err != nil {
		return slog.New(stdoutHandler), noop, fmt.Errorf("creating OTLP log exporter: %w", err)
	}

	res, err := newResource(ctx, serviceName)
	if err != nil {
		return slog.New(stdoutHandler), noop, err
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)
	global.SetLoggerProvider(provider)

	otelHandler := otelslog.NewHandler(serviceName)

	// Fan out to both — losing the collector never means losing the log
	// entirely, and losing stdout (shouldn't happen) never blocks the
	// OTLP copy either; each handler fails independently.
	handler := &multiHandler{handlers: []slog.Handler{stdoutHandler, otelHandler}}

	return slog.New(handler), provider.Shutdown, nil
}
