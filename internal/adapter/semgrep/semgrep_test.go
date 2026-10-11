package semgrep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/adapter/adaptertest"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

func opts(t *testing.T) engine.Options {
	t.Helper()
	p, _ := engine.ProfileByName("standard")
	return engine.Options{Profile: p, Scratch: t.TempDir(), Redactor: safety.NewRedactor(), Online: true}
}

// Finding 7: an offline scan without local rules is skipped with a reason
// that names the config key; the registry pack is never requested. With
// local rules, offline runs normally.
func TestOfflineWithoutLocalRulesSkips(t *testing.T) {
	a := New()
	o := opts(t)
	o.Online = false
	_, err := a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, o)
	var skip *engine.SkipError
	if !errors.As(err, &skip) || !strings.Contains(skip.Reason, "tools.semgrep_rules") || !strings.Contains(skip.Reason, DefaultConfig) {
		t.Fatalf("want SkipError naming tools.semgrep_rules, got %v", err)
	}
	p, err := a.Plan(context.Background(), domain.Target{Type: domain.TargetPath, Value: "/repo"}, o)
	if err != nil || !strings.Contains(p.Summary, "skipped") {
		t.Fatalf("plan should announce the skip: %+v %v", p, err)
	}
	o.SemgrepRules = "/opt/rules"
	args, err := a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, o)
	if err != nil || !strings.Contains(" "+strings.Join(args, " ")+" ", " --config /opt/rules ") {
		t.Fatalf("offline with local rules must run: %v %v", args, err)
	}
	for _, x := range args {
		if x == DefaultConfig {
			t.Fatalf("registry pack in offline args: %v", args)
		}
	}
	// Through Run with a fake binary: the engine is skipped, not executed.
	o.SemgrepRules = ""
	argvPath := adaptertest.Install(t, "semgrep", "--version", "1.60.0", "")
	err = a.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: t.TempDir()}, o, func(domain.Finding) error { return nil })
	if !errors.As(err, &skip) {
		t.Fatalf("Run offline without rules: %v", err)
	}
	if _, statErr := os.Stat(argvPath); statErr == nil {
		t.Fatal("semgrep binary was executed on an offline scan without local rules")
	}
}

func parseFixture(t *testing.T, version, root string) (map[string]domain.Finding, error) {
	t.Helper()
	f, err := os.Open(filepath.Join(adaptertest.FixtureDir(t, "semgrep", version), "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a := New()
	a.root = root
	out := map[string]domain.Finding{}
	err = a.Parse(f, func(fd domain.Finding) error { out[fd.RuleID] = fd; return nil })
	return out, err
}

// Two semgrep versions parse to the expected findings; the newer fixture
// carries hostile elements that are skipped and counted.
func TestParseFixtures(t *testing.T) {
	got, err := parseFixture(t, "1.60.0", "/repo/root")
	if err != nil || len(got) != 3 {
		t.Fatalf("1.60.0: %d findings, err %v", len(got), err)
	}
	sub := got["semgrep:python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use"]
	if sub.Severity != domain.High || sub.CWE != "CWE-78" || sub.Location != "app/run.py:12" || sub.Confidence != domain.Tentative || sub.AssetKey != "repo:/repo/root" || len(sub.References) != 1 {
		t.Fatalf("%+v", sub)
	}
	cookie := got["semgrep:javascript.express.security.audit.express-cookie-session-no-secure.express-cookie-session-no-secure"]
	if cookie.Severity != domain.Medium || cookie.Confidence != domain.Firm || cookie.CWE != "CWE-614" || !strings.Contains(cookie.WhatItIs, "description from semgrep") {
		t.Fatalf("%+v", cookie)
	}
	if strings.Contains(cookie.Evidence[0].Redacted, "s3cr3t-session-key-value") {
		t.Fatalf("session secret leaked: %q", cookie.Evidence[0].Redacted)
	}
	aws := got["semgrep:generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"]
	if aws.Severity != domain.Info || strings.Contains(aws.Evidence[0].Redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("aws key leaked: %+v", aws)
	}

	got, err = parseFixture(t, "1.100.0", "/repo/root")
	if err == nil || !strings.Contains(err.Error(), "4 element(s)") {
		t.Fatalf("hostile elements must be reported: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("1.100.0: %d findings %v", len(got), got)
	}
	// Absolute path under the root is made relative.
	if got["semgrep:python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use"].Location != "app/run.py:12" {
		t.Fatal("absolute path not relativised")
	}
	for id := range got {
		if strings.Contains(id, "..") || strings.Contains(id, "bad-severity") || strings.Contains(id, "escape") {
			t.Fatalf("hostile element accepted: %s", id)
		}
	}
	c := got["semgrep:javascript.express.security.audit.express-cookie-session-no-secure.express-cookie-session-no-secure"]
	if strings.ContainsAny(c.WhatItIs, "\x00\x07") || strings.Contains(c.Evidence[0].Redacted, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") || len(c.References) != 1 {
		t.Fatalf("control chars or token leaked: %+v", c)
	}
	if err := New().Parse(strings.NewReader(`["not","an","object"]`), nil); err == nil {
		t.Fatal("non-object accepted")
	}
	if err := New().Parse(strings.NewReader(`{"results": [{"check_id": "a.b", "path": "x", "start": {"line": 1}, "extra": {"severity": "ERROR"}`), nil); err == nil {
		t.Fatal("truncated JSON accepted")
	}
}

func TestArgs(t *testing.T) {
	a := New()
	o := opts(t)
	args, err := a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo/with space"}, o)
	if err != nil {
		t.Fatal(err)
	}
	j := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" scan ", " --config p/default ", " --metrics=off ", " --disable-version-check ", " --oss-only ", " --json ", " --output " + filepath.Join(o.Scratch, outputFile) + " ", " -- /repo/with space "} {
		if !strings.Contains(j, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	if err := adapter.CheckForbidden(args); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"--autofix", "--pro", "--metrics=on", "--metrics=auto", "auto"} {
		for _, x := range args {
			if x == bad {
				t.Fatalf("forbidden %q in %v", bad, args)
			}
		}
	}
	o.SemgrepRules = "/opt/rules"
	args, _ = a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, o)
	if !strings.Contains(" "+strings.Join(args, " ")+" ", " --config /opt/rules ") {
		t.Fatalf("local rules not used: %v", args)
	}
	o.SemgrepRules = "relative/rules"
	if _, err := a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, o); err == nil {
		t.Fatal("relative rules path accepted")
	}
	if _, err := a.Args(domain.Target{Type: domain.TargetPath, Value: "-rf"}, o); err == nil {
		t.Fatal("flag-shaped path accepted")
	}
	// --config auto is refused at the exec boundary even if a builder regressed.
	if err := adapter.CheckForbidden([]string{"scan", "--config", "auto"}); err == nil {
		t.Fatal("--config auto accepted")
	}
	if err := adapter.CheckForbidden([]string{"scan", "--config=auto"}); err == nil {
		t.Fatal("--config=auto accepted")
	}
}

func TestRunWithFakeBinary(t *testing.T) {
	fixture := filepath.Join(adaptertest.FixtureDir(t, "semgrep", "1.60.0"), "results.json")
	argvPath := adaptertest.Install(t, "semgrep", "--version", "1.60.0", copyToOutput(fixture))
	a := New()
	o := opts(t)
	root := t.TempDir()
	n := 0
	err := a.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: root}, o, func(f domain.Finding) error { n++; return nil })
	if err != nil || n != 3 || a.Version() != "1.60.0" {
		t.Fatalf("n=%d version=%q err=%v", n, a.Version(), err)
	}
	argv := adaptertest.Argv(t, argvPath)
	j := " " + strings.Join(argv, " ") + " "
	for _, want := range []string{" --metrics=off ", " --config p/default ", " -- " + root + " "} {
		if !strings.Contains(j, want) {
			t.Errorf("argv missing %q: %v", want, argv)
		}
	}
	// Too old -> skipped with doctor hint.
	adaptertest.Install(t, "semgrep", "--version", "1.20.0", "")
	err = New().Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: root}, o, nil)
	var skip *engine.SkipError
	if !errors.As(err, &skip) || !strings.Contains(skip.Reason, "doctor") {
		t.Fatalf("old semgrep should skip: %v", err)
	}
	adaptertest.Hide(t)
	if err := New().Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: root}, o, nil); !errors.As(err, &skip) {
		t.Fatalf("missing semgrep should skip: %v", err)
	}
}

// copyToOutput writes file to the path after --output (builtins only).
func copyToOutput(file string) string {
	return `OUT2=''; prev=''; for a in "$@"; do if [ "$prev" = "--output" ]; then OUT2="$a"; fi; prev="$a"; done; : > "$OUT2"; while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line" >> "$OUT2"; done < '` + file + `'`
}
