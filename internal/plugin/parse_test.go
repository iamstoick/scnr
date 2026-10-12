package plugin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// parseEngine builds a minimal engine for parse unit tests.
func parseEngine() *Engine {
	m := &Manifest{Name: "parse", Version: "1.0.0"}
	rules := []domain.Rule{{
		ID: "plugin.parse.ok-rule", Engine: "plugin:parse",
		Title: "Ok", Severity: "low", WhatItIs: "w", WhyItMatters: "y", HowToFix: "f",
	}}
	return &Engine{manifest: m, rules: rules}
}

func parseTarget() domain.Target {
	return domain.Target{Type: domain.TargetPath, Value: "/repo"}
}

func parseOpts() engine.Options {
	return engine.Options{Profile: engine.Profile{Name: "standard"}, Redactor: safety.NewRedactor()}
}

func parseAll(t *testing.T, e *Engine, target domain.Target, input string) ([]domain.Finding, error) {
	t.Helper()
	var got []domain.Finding
	err := e.parse(target, parseOpts(), strings.NewReader(input), func(f domain.Finding) error {
		got = append(got, f)
		return nil
	})
	return got, err
}

// E6: the child cannot emit undeclared rules, smuggle enrichment, or
// point findings outside the target.
func TestParseHardening(t *testing.T) {
	e := parseEngine()

	t.Run("undeclared-rule-fails", func(t *testing.T) {
		_, err := parseAll(t, e, parseTarget(), "{\"rule\":\"nope\",\"location\":\"a\"}\n")
		if err == nil || !strings.Contains(err.Error(), "undeclared rule") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unknown-field-fails", func(t *testing.T) {
		for _, line := range []string{
			"{\"rule\":\"ok-rule\",\"location\":\"a\",\"kev\":true}\n",
			"{\"rule\":\"ok-rule\",\"location\":\"a\",\"cvss\":{\"score\":9.8}}\n",
			"{\"rule\":\"ok-rule\",\"location\":\"a\",\"severity\":\"critical\"}\n",
		} {
			if _, err := parseAll(t, e, parseTarget(), line); err == nil {
				t.Fatalf("line accepted: %s", line)
			}
		}
	})

	t.Run("bad-json-fails", func(t *testing.T) {
		if _, err := parseAll(t, e, parseTarget(), "not json\n"); err == nil {
			t.Fatal("bad JSON accepted")
		}
	})

	t.Run("path-escape-dropped", func(t *testing.T) {
		got, err := parseAll(t, e, parseTarget(),
			"{\"rule\":\"ok-rule\",\"location\":\"../escape\"}\n"+
				"{\"rule\":\"ok-rule\",\"location\":\"/etc/passwd\"}\n"+
				"{\"rule\":\"ok-rule\",\"location\":\"sub/ok.js\"}\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Location != "sub/ok.js" {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("url-origin-pinned", func(t *testing.T) {
		target := domain.Target{Type: domain.TargetURL, Value: "https://example.com/app"}
		got, err := parseAll(t, e, target,
			"{\"rule\":\"ok-rule\",\"location\":\"https://example.com/app/a?x=1#f\"}\n"+
				"{\"rule\":\"ok-rule\",\"location\":\"https://evil.com/app/a\"}\n"+
				"{\"rule\":\"ok-rule\",\"location\":\"/relative\"}\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
		if got[0].Location != "https://example.com/app/a?x=1" {
			t.Fatalf("location = %q", got[0].Location)
		}
	})

	t.Run("caps-enforced", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("{\"rule\":\"ok-rule\",\"location\":\"a\",\"references\":[")
		for i := 0; i < 20; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("\"https://example.com/r" + string(rune('a'+i)) + "\"")
		}
		b.WriteString("],\"evidence\":[")
		for i := 0; i < 20; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("{\"kind\":\"k\",\"location\":\"l\",\"text\":\"t\"}")
		}
		b.WriteString("]}\n")
		got, err := parseAll(t, e, parseTarget(), b.String())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d findings", len(got))
		}
		if len(got[0].References) != maxRefs {
			t.Fatalf("references = %d", len(got[0].References))
		}
		if len(got[0].Evidence) != maxEvidence {
			t.Fatalf("evidence = %d", len(got[0].Evidence))
		}
	})

	t.Run("oversize-line-fails", func(t *testing.T) {
		line := "{\"rule\":\"ok-rule\",\"location\":\"" + strings.Repeat("a", maxLineBytes) + "\"}\n"
		if _, err := parseAll(t, e, parseTarget(), line); err == nil {
			t.Fatal("oversize line accepted")
		}
	})

	t.Run("confidence-defaults-tentative", func(t *testing.T) {
		got, err := parseAll(t, e, parseTarget(), "{\"rule\":\"ok-rule\",\"location\":\"a\",\"confidence\":\"bogus\"}\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Confidence != domain.Tentative {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("finding-count-capped", func(t *testing.T) {
		line := "{\"rule\":\"ok-rule\",\"location\":\"a\"}\n"
		var b strings.Builder
		for i := 0; i < maxFindings+1; i++ {
			b.WriteString(line)
		}
		if _, err := parseAll(t, e, parseTarget(), b.String()); err == nil {
			t.Fatal("over-cap findings accepted")
		}
	})

	t.Run("non-url-refs-dropped", func(t *testing.T) {
		got, err := parseAll(t, e, parseTarget(),
			"{\"rule\":\"ok-rule\",\"location\":\"a\",\"references\":[\"javascript:alert(1)\",\"https://example.com/ok\",\"\",\"notaurl\"]}\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || len(got[0].References) != 1 || got[0].References[0] != "https://example.com/ok" {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("blank-lines-skipped", func(t *testing.T) {
		got, err := parseAll(t, e, parseTarget(), "\n  \n{\"rule\":\"ok-rule\",\"location\":\"a\"}\n\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d findings", len(got))
		}
	})
}

// Manifest validation is the trust root's front door: every field is
// constrained.
func TestParseManifestValidation(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{
			"protocol": 1, "name": "valid", "version": "1.2.3",
			"description": "d", "homepage": "https://example.com/valid",
			"supports": []string{"path", "url"}, "safety": "safe",
			"capabilities":  map[string]any{"network": "none", "filesystem": "target-readonly"},
			"binary_sha256": strings.Repeat("ab", 32),
			"rules":         []any{map[string]any{"id": "r1", "title": "T", "severity": "high", "what": "w", "why": "y", "fix": "f"}},
		}
	}
	encode := func(m map[string]any) []byte {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := map[string]func(m map[string]any){
		"bad-protocol": func(m map[string]any) { m["protocol"] = 2 },
		"bad-name":     func(m map[string]any) { m["name"] = "UPPER" },
		"bad-version":  func(m map[string]any) { m["version"] = "1.2" },
		"empty-desc":   func(m map[string]any) { m["description"] = "" },
		"bad-homepage": func(m map[string]any) { m["homepage"] = "ftp://x" },
		"bad-supports": func(m map[string]any) { m["supports"] = []string{"cloud"} },
		"dup-supports": func(m map[string]any) { m["supports"] = []string{"path", "path"} },
		"bad-safety":   func(m map[string]any) { m["safety"] = "intrusive" },
		"bad-network": func(m map[string]any) {
			m["capabilities"] = map[string]any{"network": "raw", "filesystem": "target-readonly"}
		},
		"bad-filesystem": func(m map[string]any) {
			m["capabilities"] = map[string]any{"network": "none", "filesystem": "readwrite"}
		},
		"bad-hash": func(m map[string]any) { m["binary_sha256"] = "zz" },
		"no-rules": func(m map[string]any) { m["rules"] = []any{} },
		"bad-rule-id": func(m map[string]any) {
			m["rules"] = []any{map[string]any{"id": "BAD ID", "title": "T", "severity": "low", "what": "w", "why": "y", "fix": "f"}}
		},
		"bad-severity": func(m map[string]any) {
			m["rules"] = []any{map[string]any{"id": "r1", "title": "T", "severity": "nonsense", "what": "w", "why": "y", "fix": "f"}}
		},
		"missing-fix": func(m map[string]any) {
			m["rules"] = []any{map[string]any{"id": "r1", "title": "T", "severity": "low", "what": "w", "why": "y"}}
		},
		"unknown-field": func(m map[string]any) { m["safety_level"] = "safe" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := valid()
			mutate(m)
			if _, _, err := ParseManifest(encode(m)); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		m, rules, err := ParseManifest(encode(valid()))
		if err != nil {
			t.Fatal(err)
		}
		if m.Name != "valid" || len(rules) != 1 || rules[0].ID != "plugin.valid.r1" {
			t.Fatalf("m = %+v rules = %+v", m, rules)
		}
	})
	if _, _, err := ParseManifest(nil); err == nil {
		t.Fatal("empty manifest accepted")
	}
	if _, _, err := ParseManifest(make([]byte, MaxManifestBytes+1)); err == nil {
		t.Fatal("oversize manifest accepted")
	}
}

func TestNormaliseLocationEdge(t *testing.T) {
	// Host targets pin host+port like URL targets.
	target := domain.Target{Type: domain.TargetHost, Value: "example.com:8443"}
	if loc, ok := normaliseLocation(target, "https://example.com:8443/a"); !ok || loc != "https://example.com:8443/a" {
		t.Fatalf("loc = %q %v", loc, ok)
	}
	if _, ok := normaliseLocation(target, "https://example.com/a"); ok {
		t.Fatal("wrong-port location accepted")
	}
	// Overlong locations are dropped everywhere.
	if _, ok := normaliseLocation(parseTarget(), strings.Repeat("a", maxLocation+1)); ok {
		t.Fatal("overlong location accepted")
	}
	// Cleaning: sub/../x stays inside and is cleaned.
	if loc, ok := normaliseLocation(parseTarget(), "sub/../x"); !ok || loc != "x" {
		t.Fatalf("loc = %q %v", loc, ok)
	}
}
