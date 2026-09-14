package telemetry

import (
	"context"
	"errors"
	"log/slog"
)

// multiHandler fans a single log record out to several slog.Handlers,
// same idea as io.MultiWriter but for structured logging — the standard
// library doesn't ship one. Used to send every record both to stdout
// (unconditionally) and to the OTLP exporter (when telemetry is enabled)
// without picking one or the other.
type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs error
	for _, h := range m.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		// r.Clone() — a slog.Record's Attrs can only be iterated once;
		// each handler needs its own pass over them.
		if err := h.Handle(ctx, r.Clone()); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: next}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: next}
}
