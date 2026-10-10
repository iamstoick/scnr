package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/gerald/scnr/internal/safety"
)

func TestRedactingHandler(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Level: slog.LevelDebug, Out: &buf, IsTTY: false, Redactor: safety.NewRedactor()})
	log.With("ctx", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789").
		WithGroup("g").
		Info("found key AKIAIOSFODNN7EXAMPLE", "password", "password=hunter2secret", slog.Group("nested", slog.String("k", "AKIAIOSFODNN7EXAMPLE")))
	out := buf.String()
	for _, raw := range []string{"IOSFODNN7EXAMPLE", "abcdefghijklmnopqrstuvwxyz0123456789", "hunter2secret"} {
		if strings.Contains(out, raw) {
			t.Fatalf("secret leaked into log: %s", out)
		}
	}
	if !strings.Contains(out, `"msg":"found key AKIA`) || !strings.Contains(out, "ctx") {
		t.Fatalf("unexpected log line: %s", out)
	}
	buf.Reset()
	New(Options{Out: &buf, IsTTY: true}).Info("plain")
	if !strings.HasPrefix(buf.String(), "time=") {
		t.Fatalf("TTY should use text handler: %s", buf.String())
	}
}
