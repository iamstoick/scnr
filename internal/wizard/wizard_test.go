package wizard

import (
	"strings"
	"testing"
)

func TestFlagsIntrusiveAuth(t *testing.T) {
	r := ScanRequest{Targets: []string{"http://127.0.0.1/"}, AllowIntrusive: true, AuthFile: "/tmp/a.yaml",
		Headers: []string{"X: s3cr3t-value"}, Cookies: []string{"s=tok"}, Formats: "html,json"}
	out := r.Flags()
	for _, want := range []string{"--allow-intrusive", "--auth-file /tmp/a.yaml"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	// Header and cookie values must never reach the reproducible command.
	for _, bad := range []string{"--header", "--cookie", "s3cr3t", "s=tok"} {
		if strings.Contains(out, bad) {
			t.Fatalf("leaked %q in %q", bad, out)
		}
	}
}
