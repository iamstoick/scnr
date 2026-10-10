package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gerald/scnr/internal/domain"
)

func TestPolicyParseAndEvaluate(t *testing.T) {
	for name, in := range map[string]string{
		"unknown field": "fail_on: high\nbogus: 1\n",
		"bad bucket":    "fail_on: urgent\n",
		"bad max":       "max_findings: {severe: 1}\n",
		"neg max":       "max_findings: {high: -1}\n",
		"bad score":     "min_score: 101\n",
		"empty":         "",
	} {
		if _, err := ParsePolicy([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	p, err := ParsePolicy([]byte("fail_on: high\nfail_on_kev: true\nmax_findings: {critical: 0, medium: 2}\nmin_score: 70\nrequired_engines: [secrets, sca]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ok := PolicyInput{OpenByBucket: map[string]int{"medium": 2, "low": 9}, Score: 80, Engines: []domain.EngineRun{{Name: "secrets", Status: "ok"}, {Name: "sca", Status: "ok"}}}
	if v := p.Evaluate(ok); len(v) != 0 {
		t.Fatalf("expected pass: %v", v)
	}
	bad := PolicyInput{OpenByBucket: map[string]int{"critical": 1, "high": 1, "medium": 3}, KEVOpen: true, Score: 40, Engines: []domain.EngineRun{{Name: "secrets", Status: "skipped: offline"}}}
	v := p.Evaluate(bad)
	joined := strings.Join(v, "\n")
	for _, want := range []string{"fail_on high: 2 open", "fail_on_kev", "max_findings.critical: 1 open > 0", "max_findings.medium: 3 open > 2", "min_score: posture 40 < 70", "required_engines: sca did not run", "required_engines: secrets skipped: offline"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if len(v) != 7 {
		t.Fatalf("got %d violations: %v", len(v), v)
	}
	// fail_on_partial: strict field, default off, fails when any engine did not complete.
	if _, err := ParsePolicy([]byte("fail_on_partial: yes please\n")); err == nil {
		t.Error("non-boolean fail_on_partial accepted")
	}
	pp, err := ParsePolicy([]byte("fail_on_partial: true\n"))
	if err != nil || !pp.FailOnPartial {
		t.Fatalf("fail_on_partial alone is a valid policy: %v", err)
	}
	if v := pp.Evaluate(PolicyInput{Partial: false, Engines: []domain.EngineRun{{Name: "secrets", Status: "ok"}}}); len(v) != 0 {
		t.Errorf("complete scan must pass: %v", v)
	}
	v = pp.Evaluate(PolicyInput{Partial: true, Engines: []domain.EngineRun{{Name: "secrets", Status: "ok"}, {Name: "adapter:nuclei", Status: "skipped: nuclei unavailable"}, {Name: "sca", Status: "failed", Error: "timed out"}}})
	if len(v) != 1 || !strings.Contains(v[0], "fail_on_partial: adapter:nuclei (skipped: nuclei unavailable), sca (failed)") {
		t.Errorf("partial scan must fail with the incomplete engines named: %v", v)
	}
	if !p.FailOnPartial {
		if v := p.Evaluate(PolicyInput{Partial: true, OpenByBucket: map[string]int{}, Score: 100, Engines: []domain.EngineRun{{Name: "secrets", Status: "ok"}, {Name: "sca", Status: "ok"}}}); len(v) != 0 {
			t.Errorf("fail_on_partial defaults to off: %v", v)
		}
	}
	// Accepted findings are not counted: the caller only passes open counts.
	p2, _ := ParsePolicy([]byte("fail_on: high\n"))
	if v := p2.Evaluate(PolicyInput{OpenByBucket: map[string]int{}}); len(v) != 0 {
		t.Fatal(v)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte("fail_on: high\n"), 0o600)
	if lp, err := LoadPolicy(path); err != nil || lp.Path != path {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing policy accepted")
	}
}

func TestBaseline(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	bl := &Baseline{Version: BaselineVersion, CreatedFrom: "scan1", Fingerprints: []string{fp}, Rules: []string{"net.open-port", "nuclei:CVE-2021-1"}}
	b, err := bl.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBaseline(b)
	if err != nil || len(got.Fingerprints) != 1 || len(got.Rules) != 2 || got.CreatedFrom != "scan1" {
		t.Fatalf("%+v %v", got, err)
	}
	for name, in := range map[string]string{
		"unknown field": "version: 1\nfingerprints: []\nextra: 1\n",
		"bad version":   "version: 2\nfingerprints: []\n",
		"bad fp":        "version: 1\nfingerprints: ['not-hex']\n",
		"bad rule":      "version: 1\nfingerprints: []\nrules: ['a b']\n",
	} {
		if _, err := ParseBaseline([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	path := filepath.Join(t.TempDir(), "b.yaml")
	os.WriteFile(path, b, 0o600)
	if _, err := LoadBaseline(path); err != nil {
		t.Fatal(err)
	}
}
