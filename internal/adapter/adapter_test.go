package adapter

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDetectAndExecWithGoBinary(t *testing.T) {
	// The Go toolchain is the one binary guaranteed present in CI; its
	// "version" subcommand stands in for a tool's --version.
	b := &Base{BinaryName: "go", VersionArgs: []string{"version"}, Min: "1.20"}
	info, err := b.Detect(context.Background())
	if err != nil || !info.OK || info.Path == "" || info.Version == "" {
		t.Fatalf("%+v %v", info, err)
	}
	strict := &Base{BinaryName: "go", VersionArgs: []string{"version"}, Min: "99.0"}
	if info, _ := strict.Detect(context.Background()); info.OK || !strings.Contains(info.Reason, "older") {
		t.Fatalf("min version not enforced: %+v", info)
	}
	if info, _ := (&Base{BinaryName: "scnr-definitely-missing"}).Detect(context.Background()); info.OK || info.Reason == "" {
		t.Fatalf("missing binary: %+v", info)
	}
	scratch := t.TempDir()
	res, err := b.Exec(context.Background(), scratch, []string{"env", "GOOS"}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(res.StdoutPath)
	if strings.TrimSpace(string(out)) == "" || res.ExitCode != 0 {
		t.Fatalf("stdout %q exit %d", out, res.ExitCode)
	}
	// Non-zero exit is reported, not an error.
	res, err = b.Exec(context.Background(), scratch, []string{"env", "-bogus-flag"}, 10*time.Second)
	if err != nil || res.ExitCode == 0 || res.StderrTail == "" {
		t.Fatalf("exit=%d err=%v stderr=%q", res.ExitCode, err, res.StderrTail)
	}
	if _, err := b.Exec(context.Background(), scratch, []string{"a\x00b"}, time.Second); err == nil {
		t.Fatal("NUL in argv accepted")
	}
	if _, err := (&Base{BinaryName: "x"}).Exec(context.Background(), scratch, nil, time.Second); err == nil {
		t.Fatal("Exec before Detect must fail")
	}
}

func TestEnvIsMinimal(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "leak")
	t.Setenv("HOME", "/h")
	env := (&Base{}).env()
	for _, kv := range env {
		if strings.HasPrefix(kv, "AWS_") {
			t.Fatalf("env leaked: %v", env)
		}
	}
	found := false
	for _, kv := range (&Base{ExtraEnv: []string{"AWS_SECRET_ACCESS_KEY"}}).env() {
		if kv == "AWS_SECRET_ACCESS_KEY=leak" {
			found = true
		}
	}
	if !found {
		t.Fatal("ExtraEnv not passed through")
	}
}

func TestCappedWriterAndTail(t *testing.T) {
	tb := &tailBuffer{max: 5}
	tb.Write([]byte("abcdefgh"))
	if tb.String() != "defgh" {
		t.Fatalf("tail %q", tb.String())
	}
	if CompareVersions("7.94", "7.80") != 1 || CompareVersions("3.1.0", "3.1") != 0 || CompareVersions("1.9", "1.10") != -1 {
		t.Fatal("CompareVersions")
	}
}
