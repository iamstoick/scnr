// Package logx configures slog: text for TTYs, JSON otherwise, with a
// redacting handler so secrets never reach log output.
package logx

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Redactor is the subset of safety.Redactor logx needs; declared here to
// avoid an import cycle (safety imports logx for its own logging).
type Redactor interface {
	Redact(string) string
}

// Options for New.
type Options struct {
	Level    slog.Level
	Out      io.Writer // defaults to os.Stderr
	IsTTY    bool
	Redactor Redactor // optional
}

// New returns a configured logger.
func New(o Options) *slog.Logger {
	if o.Out == nil {
		o.Out = os.Stderr
	}
	ho := &slog.HandlerOptions{Level: o.Level}
	var h slog.Handler
	if o.IsTTY {
		h = slog.NewTextHandler(o.Out, ho)
	} else {
		h = slog.NewJSONHandler(o.Out, ho)
	}
	if o.Redactor != nil {
		h = &redactingHandler{Handler: h, r: o.Redactor}
	}
	return slog.New(h)
}

type redactingHandler struct {
	slog.Handler
	r Redactor
}

func (h *redactingHandler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.r.Redact(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.Handler.Handle(ctx, out)
}

func (h *redactingHandler) redactAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.r.Redact(a.Value.String()))
	case slog.KindGroup:
		attrs := a.Value.Group()
		redacted := make([]any, 0, len(attrs))
		for _, g := range attrs {
			redacted = append(redacted, h.redactAttr(g))
		}
		return slog.Group(a.Key, redacted...)
	}
	return a
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	for i := range attrs {
		attrs[i] = h.redactAttr(attrs[i])
	}
	return &redactingHandler{Handler: h.Handler.WithAttrs(attrs), r: h.r}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{Handler: h.Handler.WithGroup(name), r: h.r}
}
