package codecheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

const fixtureRepo = "../../../testdata/phase3-repo"

// Acceptance 3.6: every finding is Tentative and carries the verify text.
func TestFixtureRepoFindingsAreTentative(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if RuleCount() < 30 {
		t.Fatalf("only %d rules", RuleCount())
	}
	abs, _ := filepath.Abs(fixtureRepo)
	got := map[string][]string{}
	err = e.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: abs}, engine.Options{Redactor: safety.NewRedactor()}, func(f domain.Finding) error {
		if f.Confidence != domain.Tentative {
			t.Errorf("%s not tentative", f.RuleID)
		}
		if !strings.Contains(f.WhatItIs, "verify in context") {
			t.Errorf("%s lacks verify text: %q", f.RuleID, f.WhatItIs)
		}
		if len(f.Evidence) != 1 || f.Evidence[0].Redacted == "" {
			t.Errorf("%s evidence %+v", f.RuleID, f.Evidence)
		}
		got[f.RuleID] = append(got[f.RuleID], f.Location)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"code.debug-true-config":      "src/app.py:3",
		"code.tls-verify-disabled":    "src/app.py:6",
		"code.shell-injection":        "src/app.py:9",
		"code.sql-concat":             "src/app.py:12",
		"code.unsafe-deserialization": "src/app.py:15",
		"code.weak-hash":              "src/app.py:18",
		"code.cors-wildcard":          "web/server.js:3",
		"code.open-redirect":          "web/server.js:4",
		"code.path-from-request":      "web/server.js:5",
		"code.insecure-random-secret": "web/server.js:6",
		"code.bind-all-interfaces":    "web/server.js:7",
		"code.docker-socket-mount":    "docker-compose.yml:5",
	}
	for rule, loc := range want {
		found := false
		for _, l := range got[rule] {
			if l == loc {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: got %v, want %s", rule, got[rule], loc)
		}
	}
	// The Dockerfile ADD/curl lines are IaC's job, not codecheck's; comments never match.
	if len(got["code.curl-pipe-shell"]) != 0 {
		t.Errorf("curl-pipe-shell %v", got["code.curl-pipe-shell"])
	}
}

func TestScanContentScopingAndComments(t *testing.T) {
	// Python-only pattern does not fire in Go; comment lines are skipped.
	if m := ScanContent("x.go", []byte("verify = False\n")); len(m) != 0 {
		t.Fatalf("%v", m)
	}
	if m := ScanContent("x.py", []byte("# verify=False\nverify=False\n")); len(m) != 1 || m[0].Line != 2 {
		t.Fatalf("%v", m)
	}
	// http URL filter: documentation/namespace hosts are not findings.
	if m := ScanContent("x.py", []byte(`ns = "http://www.w3.org/2000/svg"`+"\n"+`u = "http://localhost:8080/x"`+"\n"+`d = "http://downloads.example-cdn.net/pkg.tgz"`+"\n")); len(m) != 1 || m[0].Line != 3 {
		t.Fatalf("%v", m)
	}
	// Per-file match cap and long lines.
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString("eval(x)\n")
	}
	if m := ScanContent("x.js", []byte(b.String())); len(m) != maxMatchesPerFile {
		t.Fatalf("%d", len(m))
	}
	long := "x = 1 " + strings.Repeat("a", 10000) + " eval(x)\n"
	ScanContent("x.js", []byte(long)) // truncated line, no panic
	// Secret-looking excerpt is redacted before it becomes evidence.
	e, _ := New()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.js"), []byte(`console.log("api_key", api_key, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")`+"\n"), 0o600)
	e.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: dir}, engine.Options{Redactor: safety.NewRedactor()}, func(f domain.Finding) error {
		if strings.Contains(f.Evidence[0].Redacted, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
			t.Fatalf("token leaked: %q", f.Evidence[0].Redacted)
		}
		return nil
	})
}

func FuzzScanContent(f *testing.F) {
	f.Add("x.py", []byte("verify=False\n"))
	f.Add("x.js", []byte("eval(`${a}`)\n"))
	f.Fuzz(func(t *testing.T, name string, b []byte) {
		ScanContent(name, b)
	})
}
