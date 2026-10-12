package plugin

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// installSigned stages and installs one plugin version, returning home.
func installSigned(t *testing.T, name, version string, bin []byte, mutate func(m map[string]any)) (home string, pub ed25519.PublicKey) {
	t.Helper()
	home = t.TempDir()
	var priv ed25519.PrivateKey
	pub, priv = testKey(t)
	stage := t.TempDir()
	raw := stagePlugin(t, stage, name, version, bin, mutate)
	signStage(t, stage, raw, priv)
	if _, err := Install(stage, installOpts(home, pub)); err != nil {
		t.Fatal(err)
	}
	return home, pub
}

// hideWrappers empties PATH so DetectSandbox finds no wrapper.
func hideWrappers(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// E4: loading is fail-closed. Without a sandbox wrapper, mode
// "required" loads nothing and reports why; "best-effort" loads with
// the sandbox recorded as none.
func TestLoadSandboxGating(t *testing.T) {
	hideWrappers(t)
	home, _ := installSigned(t, "gate", "1.0.0", nil, nil)
	if sb := DetectSandbox(); sb != nil {
		t.Fatalf("wrapper %s visible with empty PATH", sb.Name())
	}

	var events []LoadEvent
	engines, err := Load(LoadOptions{Home: home, SandboxMode: "required",
		Audit: func(a string, d map[string]any) { events = append(events, LoadEvent{a, d}) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(engines) != 0 {
		t.Fatal("required mode loaded a plugin with no wrapper")
	}
	if len(events) != 1 || events[0].Action != "plugin_integrity" {
		t.Fatalf("events = %+v", events)
	}

	engines, err = Load(LoadOptions{Home: home, SandboxMode: "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if len(engines) != 1 {
		t.Fatalf("best-effort loaded %d engines", len(engines))
	}
	pi, ok := engines[0].(interface {
		PluginInfo() (string, string, string)
	})
	if !ok {
		t.Fatal("engine has no PluginInfo")
	}
	n, v, s := pi.PluginInfo()
	if n != "gate" || v != "1.0.0" || s != "none (best-effort)" {
		t.Fatalf("PluginInfo = %q %q %q", n, v, s)
	}
	if engines[0].Name() != "plugin:gate" {
		t.Fatalf("name = %q", engines[0].Name())
	}
}

// E4: a plugin that drifts after install never loads; the newest
// installed version is the one that runs.
func TestLoadSkipsDrift(t *testing.T) {
	hideWrappers(t)
	home := t.TempDir()
	pub, priv := testKey(t)
	for _, v := range []string{"1.0.0", "1.1.0"} {
		stage := t.TempDir()
		raw := stagePlugin(t, stage, "driftload", v, nil, nil)
		signStage(t, stage, raw, priv)
		if _, err := Install(stage, installOpts(home, pub)); err != nil {
			t.Fatal(err)
		}
	}
	engines, err := Load(LoadOptions{Home: home, SandboxMode: "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if len(engines) != 1 || engines[0].(interface{ Version() string }).Version() != "1.1.0" {
		t.Fatal("newest version is not the one loaded")
	}
	l, _ := LoadLock(home)
	e, _ := l.Find("driftload", "1.1.0")
	f, _ := os.OpenFile(BinaryPath(home, e), os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.Write([]byte("x"))
	_ = f.Close()
	var events []LoadEvent
	engines, err = Load(LoadOptions{Home: home, SandboxMode: "best-effort",
		Audit: func(a string, d map[string]any) { events = append(events, LoadEvent{a, d}) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(engines) != 0 {
		t.Fatal("drifted plugin loaded")
	}
	if len(events) != 1 || events[0].Action != "plugin_integrity" {
		t.Fatalf("events = %+v", events)
	}
}

// E4: a broken lock file fails loudly instead of scanning with an
// unknown plugin set.
func TestLoadBrokenLock(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, PluginsDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, LockFileName), []byte("plugins: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(LoadOptions{Home: home}); err == nil {
		t.Fatal("broken lock loaded")
	}
}

func TestEngineSupports(t *testing.T) {
	hideWrappers(t)
	home, _ := installSigned(t, "sup", "1.0.0", nil, nil)
	engines, err := Load(LoadOptions{Home: home, SandboxMode: "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	e := engines[0]
	if !e.Supports(domain.Target{Type: domain.TargetPath, Value: "/tmp/x"}) {
		t.Fatal("path plugin does not support path targets")
	}
	if e.Supports(domain.Target{Type: domain.TargetURL, Value: "https://example.com"}) {
		t.Fatal("path plugin supports url targets")
	}

	netHome, _ := installSigned(t, "net", "1.0.0", nil, func(m map[string]any) {
		m["supports"] = []string{"path", "url", "host"}
		m["capabilities"] = map[string]any{"network": "broker", "filesystem": "target-readonly"}
	})
	netEngines, err := Load(LoadOptions{Home: netHome, SandboxMode: "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	ne := netEngines[0]
	if !ne.Supports(domain.Target{Type: domain.TargetURL, Value: "https://example.com"}) {
		t.Fatal("broker plugin does not support url targets")
	}
	// A network plugin on a path target has no origin to pin: unsupported
	// even though "path" is declared.
	if ne.Supports(domain.Target{Type: domain.TargetPath, Value: "/tmp/x"}) {
		t.Fatal("broker plugin supports path targets")
	}
}

// scriptBinary returns a /bin/sh payload that swallows stdin and prints
// lines to stdout (or, with fail, an exit code and stderr text).
func scriptBinary(lines []string, fail string) []byte {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n/bin/cat > /dev/null\n")
	for _, l := range lines {
		b.WriteString("printf '%s\\n' '" + strings.ReplaceAll(l, "'", "'\\''") + "'\n")
	}
	if fail != "" {
		b.WriteString(fail + "\n")
	}
	return []byte(b.String())
}

func runOpts() engine.Options {
	return engine.Options{
		Scratch:  "",
		Profile:  engine.Profile{Name: "standard"},
		Redactor: safety.NewRedactor(),
	}
}

// Acceptance: a plugin's two findings arrive namespaced, with rule
// text from the signed manifest, not the child.
func TestRunEmitsFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake plugin is a shell script")
	}
	hideWrappers(t)
	target := t.TempDir()
	bin := scriptBinary([]string{
		`{"rule":"ok-rule","location":"sub/f.js","confidence":"firm","evidence":[{"kind":"match","location":"sub/f.js","text":"hello"}]}`,
		`{"rule":"ok-rule","location":"` + target + `/abs/f.js","confidence":"confirmed","cves":["CVE-2024-1234","bogus"]}`,
	}, "")
	home, _ := installSigned(t, "emit", "1.0.0", bin, nil)
	engines, err := Load(LoadOptions{Home: home, SandboxMode: "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	o := runOpts()
	o.Scratch = t.TempDir()
	var got []domain.Finding
	err = engines[0].Run(context.Background(),
		domain.Target{Type: domain.TargetPath, Value: target}, o,
		func(f domain.Finding) error { got = append(got, f); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d", len(got))
	}
	if got[0].RuleID != "plugin.emit.ok-rule" || got[0].Title != "Ok rule" {
		t.Fatalf("finding 0 = %+v", got[0])
	}
	if got[0].Location != "sub/f.js" || got[0].Confidence != domain.Firm {
		t.Fatalf("finding 0 location/confidence = %q %v", got[0].Location, got[0].Confidence)
	}
	if len(got[0].Evidence) != 1 || got[0].Evidence[0].Redacted != "hello" {
		t.Fatalf("evidence = %+v", got[0].Evidence)
	}
	// Absolute paths inside the target are relativised and only
	// valid CVEs survive.
	if got[1].Location != "abs/f.js" {
		t.Fatalf("finding 1 location = %q", got[1].Location)
	}
	if len(got[1].CVEs) != 1 || got[1].CVEs[0] != "CVE-2024-1234" {
		t.Fatalf("cves = %v", got[1].CVEs)
	}
	if got[1].Confidence != domain.Confirmed {
		t.Fatalf("confidence = %v", got[1].Confidence)
	}
	if got[0].Engine != "" {
		t.Fatalf("engine sets Engine itself (%q); the runner owns that", got[0].Engine)
	}
}

// Acceptance: the child sees the documented request on stdin.
func TestRunRequestShape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake plugin is a shell script")
	}
	hideWrappers(t)
	// Echo stdin to stderr and fail: the redacted tail lands in the error.
	bin := []byte("#!/bin/sh\n/bin/cat >&2\nexit 3\n")
	home, _ := installSigned(t, "reqshape", "1.0.0", bin, nil)
	engines, err := Load(LoadOptions{Home: home, SandboxMode: "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	o := runOpts()
	o.Scratch = t.TempDir()
	target := t.TempDir()
	err = engines[0].Run(context.Background(),
		domain.Target{Type: domain.TargetPath, Value: target}, o,
		func(f domain.Finding) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "exited 3") {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{`"protocol":1`, `"type":"path"`, `"value":"` + target + `"`, `"broker":""`, `"profile":"standard"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("request lacks %s: %v", want, err)
		}
	}
}

// Acceptance: a failing child fails the engine with a redacted tail,
// and a swapped binary at run time skips instead of running.
func TestRunFailureModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake plugin is a shell script")
	}
	hideWrappers(t)

	t.Run("stderr-redacted", func(t *testing.T) {
		bin := []byte("#!/bin/sh\n/bin/cat > /dev/null\necho '{\"password\": \"hunter2-hunter2-hunter2\"} boom' >&2\nexit 1\n")
		home, _ := installSigned(t, "redact", "1.0.0", bin, nil)
		engines, _ := Load(LoadOptions{Home: home, SandboxMode: "best-effort"})
		o := runOpts()
		o.Scratch = t.TempDir()
		err := engines[0].Run(context.Background(),
			domain.Target{Type: domain.TargetPath, Value: t.TempDir()}, o,
			func(f domain.Finding) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "exited 1") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "hunter2-hunter2-hunter2") {
			t.Fatalf("secret leaked into error: %v", err)
		}
	})

	t.Run("run-time-drift-skips", func(t *testing.T) {
		home, _ := installSigned(t, "rundrift", "1.0.0", scriptBinary(nil, ""), nil)
		engines, _ := Load(LoadOptions{Home: home, SandboxMode: "best-effort"})
		l, _ := LoadLock(home)
		e, _ := l.Find("rundrift", "1.0.0")
		if err := os.WriteFile(BinaryPath(home, e), []byte("swapped"), 0o700); err != nil {
			t.Fatal(err)
		}
		o := runOpts()
		o.Scratch = t.TempDir()
		err := engines[0].Run(context.Background(),
			domain.Target{Type: domain.TargetPath, Value: t.TempDir()}, o,
			func(f domain.Finding) error { return nil })
		var skip *engine.SkipError
		if !errors.As(err, &skip) || !strings.Contains(err.Error(), "integrity failure") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		home, _ := installSigned(t, "slowscript", "1.0.0", []byte("#!/bin/sh\n/bin/sleep 30\n"), nil)
		engines, _ := Load(LoadOptions{Home: home, SandboxMode: "best-effort"})
		o := runOpts()
		o.Scratch = t.TempDir()
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		err := engines[0].Run(ctx,
			domain.Target{Type: domain.TargetPath, Value: t.TempDir()}, o,
			func(f domain.Finding) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v", err)
		}
	})
}
