package adapter

import (
	"context"
	"os"
	"runtime"
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

// A timed-out child that forked a grandchild must not hold Exec open:
// the grandchild inherits the stdout pipe, so only a group kill lets
// the copy finish. (Unix: Setpgid is a no-op on Windows.)
func TestExecTimeoutKillsProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups are Unix-only")
	}
	b := &Base{BinaryName: "sh", Setpgid: true}
	b.UsePath("/bin/sh", "test")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := b.Exec(ctx, t.TempDir(), []string{"-c", "exec /bin/sleep 30"}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	// exec replaces the shell, so this is the plain-child case. The
	// grandchild case below is the one that used to stall.
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("Exec returned after %v", d)
	}

	b2 := &Base{BinaryName: "sh", Setpgid: true}
	b2.UsePath("/bin/sh", "test")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	start = time.Now()
	_, err = b2.Exec(ctx2, t.TempDir(), []string{"-c", "/bin/sleep 30"}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("grandchild err = %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("Exec with grandchild returned after %v", d)
	}
}
