package adapter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/safety"
)

func TestStreamArray(t *testing.T) {
	in := `{"meta": {"deep": [1, {"x": null}]}, "items": [{"a": 1}, "bad", {"a": 2}, {"a": "str"}], "tail": 3}`
	var got []int
	bad, err := StreamArray(strings.NewReader(in), "items", func(dec *json.Decoder) error {
		var v struct{ A int }
		if err := DecodeElement(dec, &v); err != nil {
			return err
		}
		if v.A == 0 {
			return ErrSkipElement
		}
		got = append(got, v.A)
		return nil
	})
	if err != nil || bad != 2 || len(got) != 2 {
		t.Fatalf("got %v bad %d err %v", got, bad, err)
	}
	// Missing key, null key, non-array key, truncated input, non-object root.
	if bad, err := StreamArray(strings.NewReader(`{"other": 1}`), "items", nil); err != nil || bad != 0 {
		t.Fatal(err)
	}
	if _, err := StreamArray(strings.NewReader(`{"items": null}`), "items", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := StreamArray(strings.NewReader(`{"items": {"a": 1}}`), "items", nil); err == nil {
		t.Fatal("object accepted as array")
	}
	if _, err := StreamArray(strings.NewReader(`{"items": [{"a": 1}`), "items", func(dec *json.Decoder) error { var v any; return dec.Decode(&v) }); err == nil {
		t.Fatal("truncated accepted")
	}
	if _, err := StreamArray(strings.NewReader(`[1,2]`), "items", nil); err == nil {
		t.Fatal("array root accepted")
	}
}

func TestRelLocation(t *testing.T) {
	cases := []struct {
		root, in, want string
		ok             bool
	}{
		{"/repo", "/repo/a/b.py", "a/b.py", true},
		{"/repo", "a/b.py", "a/b.py", true},
		{"/repo", "./a/b.py", "a/b.py", true},
		{"", "/lib/apk/db/installed", "lib/apk/db/installed", true},
		{"/repo", "../../../etc/passwd", "", false},
		{"/repo", "/repo/../etc", "", false},
		{"/repo", "a/../../x", "", false},
		{"/repo", "", "", false},
		{"/repo", "/repo", ".", true},
		{"C:\\repo", "C:\\repo\\a\\b.py", "a/b.py", true},
		{"/repo", strings.Repeat("a", 2000), "", false},
	}
	for _, c := range cases {
		got, ok := RelLocation(c.root, c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("RelLocation(%q, %q) = %q %v, want %q %v", c.root, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestVulnFinding(t *testing.T) {
	rules := stubRules{}
	red := safety.NewRedactor()
	v := Vuln{ID: "GHSA-xxxx-yyyy-zzzz", Aliases: []string{"CVE-2020-8203"}, PURL: "pkg:npm/lodash@4.17.20?foo=bar", Name: "lodash", Version: "4.17.20", Fixed: "4.17.21", Severity: "High",
		Title: "t", Description: "d", References: []string{"https://x", "javascript:alert(1)", "http://y"}, CVSSVector: "CVSS:3.1/AV:N", CVSSScore: 7.4, CWE: "1321", Location: "package-lock.json"}
	f, ok := v.Finding(rules, red, "repo:/r", "tool")
	if !ok || f.RuleID != "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20" || f.CWE != "CWE-1321" || len(f.References) != 2 || f.CVSS.Score != 7.4 || f.Severity != domain.High {
		t.Fatalf("%+v", f)
	}
	// Fallback PURL from ecosystem; invalid inputs rejected.
	v.PURL, v.Ecosystem = "", "npm"
	if f, ok := v.Finding(rules, red, "repo:/r", "tool"); !ok || !strings.HasSuffix(f.RuleID, "@pkg:npm/lodash@4.17.20") {
		t.Fatalf("%+v", f)
	}
	for _, bad := range []Vuln{{}, {ID: "x", Name: "n", Version: "1", Location: "l"}, {ID: "CVE-1", Name: "n", Version: "1", Location: "l", Severity: "nope", Ecosystem: "npm"}, {ID: "CVE-2020-1", Name: "n", Version: "1", Location: "l", Severity: "low"}} {
		if _, ok := bad.Finding(rules, red, "repo:/r", "tool"); ok {
			t.Errorf("%+v accepted", bad)
		}
	}
	if CWE("CWE-79") != "CWE-79" || CWE("79") != "CWE-79" || CWE("x") != "" || CVE("cve-2020-1234") != "CVE-2020-1234" || CVE("CVE-1") != "" {
		t.Fatal("id helpers")
	}
	if s, ok := Severity("Negligible"); !ok || s != domain.Info {
		t.Fatal("negligible")
	}
	if _, ok := Severity("loud"); ok {
		t.Fatal("unknown severity accepted")
	}
}

type stubRules struct{}

func (stubRules) MustGet(string) domain.Rule {
	return domain.Rule{ID: "sca.vulnerable-dependency", Engine: "sca", Title: "T", Severity: "medium", WhatItIs: "w", WhyItMatters: "y", HowToFix: "f", Safety: "safe"}
}

func TestFlagSafePath(t *testing.T) {
	for _, ok := range []string{"/repo", "/repo/with space/x.tar"} {
		if err := FlagSafePath(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-rf", "relative/path", "/x\n--evil", "/x\x00"} {
		if err := FlagSafePath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
