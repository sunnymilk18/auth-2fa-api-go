package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics records, per request, a counter and a duration histogram — the
// two numbers most HTTP dashboards start from (request rate and latency,
// sliceable by status code to spot error spikes).
//
// Labeled by the route's chi *pattern* (e.g. "/auth/devices/{id}"), never
// the raw path — a raw path would put every distinct user/device id into
// its own metric series, and that cardinality explosion is exactly the
// kind of mistake that breaks a Prometheus-shaped backend (see the
// conversation this came out of: never put unbounded values in a label).
func Metrics(meter metric.Meter) func(http.Handler) http.Handler {
	requestCount, _ := meter.Int64Counter(
		"http.server.request_count",
		metric.WithDescription("Total HTTP requests received"),
		metric.WithUnit("{request}"),
	)
	requestDuration, _ := meter.Float64Histogram(
		"http.server.request_duration_seconds",
		metric.WithDescription("HTTP request duration"),
		metric.WithUnit("s"),
	)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			// Only fully populated once the router has matched a route —
			// safe to read here since this runs after next.ServeHTTP
			// returns, by which point chi has finished walking its tree.
			pattern := chi.RouteContext(r.Context()).RoutePattern()
			if pattern == "" {
				pattern = "unmatched" // 404s, or a route that panicked before matching
			}

			attrs := metric.WithAttributes(
				attribute.String("http_method", r.Method),
				attribute.String("http_route", pattern),
				attribute.Int("http_status_code", ww.Status()),
			)

			requestCount.Add(r.Context(), 1, attrs)
			requestDuration.Record(r.Context(), time.Since(start).Seconds(), attrs)
		})
	}
}
