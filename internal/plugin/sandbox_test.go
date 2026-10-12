package plugin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The sandbox wrapper binds the target read-only and the scratch
// read-write, with no network. The wrapper prefix never contains the
// plugin binary: the engine appends the verified path itself.
func TestSandboxWrap(t *testing.T) {
	sb := DetectSandbox()
	if sb == nil {
		t.Skip("no sandbox wrapper on this machine")
	}
	scratch := t.TempDir()
	target := t.TempDir()
	argv := mustWrap(t, sb, "/plugins/p/scnr-plugin-p", target, scratch)
	joined := strings.Join(argv, " ")
	switch runtime.GOOS {
	case "linux":
		for _, want := range []string{"bwrap", "--unshare-net", "--ro-bind", target, "--bind", scratch} {
			if !strings.Contains(joined, want) {
				t.Fatalf("argv lacks %q: %q", want, joined)
			}
		}
		if strings.Contains(joined, "scnr-plugin-p") {
			t.Fatalf("wrapper smuggles the binary: %q", joined)
		}
	case "darwin":
		if argv[0] != "sandbox-exec" || argv[1] != "-f" {
			t.Fatalf("argv = %q", argv)
		}
		profile, err := os.ReadFile(argv[2])
		if err != nil {
			t.Fatal(err)
		}
		ps := string(profile)
		for _, want := range []string{"(deny network*)", "(deny file-write*)", target, scratch} {
			if !strings.Contains(ps, want) {
				t.Fatalf("profile lacks %q:\n%s", want, ps)
			}
		}
		// Last-match-wins: the scratch write-allow must come after
		// the blanket write-deny.
		if strings.Index(ps, "(deny file-write*)") > strings.Index(ps, "(allow file-write*") {
			t.Fatal("write-allow sorts before write-deny")
		}
	default:
		t.Skip("no wrapper contract on " + runtime.GOOS)
	}
}

// Quote-heavy paths must survive profile rendering: one literal, no
// breakout.
func TestSandboxQuoteEscaping(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("sandbox-exec profiles are darwin-only")
	}
	sb := DetectSandbox()
	if sb == nil {
		t.Skip("no sandbox-exec on this machine")
	}
	scratch := t.TempDir()
	target := filepath.Join(t.TempDir(), `a"b\c`)
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	argv := mustWrap(t, sb, "/plugins/p/scnr-plugin-p", target, scratch)
	profile, err := os.ReadFile(argv[2])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profile), `a\"b\\c`) {
		t.Fatalf("bad quoting:\n%s", profile)
	}
}

func mustWrap(t *testing.T, sb Sandbox, binary, target, scratch string) []string {
	t.Helper()
	argv, err := sb.Wrap(binary, target, scratch, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) == 0 {
		t.Fatal("empty wrapper argv")
	}
	return argv
}
