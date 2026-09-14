package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// RequestLogger logs one structured line per request through the given
// logger — replaces chi's own middleware.Logger so request logs flow
// through the same pipeline as everything else logged via slog (always
// stdout, plus OTLP to Loki when telemetry.SetupLogging's endpoint is
// configured). Without this, only the handful of startup/shutdown lines
// in cmd/api/main.go would ever reach Loki — actual request traffic
// wouldn't, since that's what this replaces.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", chimw.GetReqID(r.Context()),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}
