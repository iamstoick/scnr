package report

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/store"
)

func seed(t *testing.T) (*store.Store, domain.Scan) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	tg := domain.Target{Raw: "./repo", Type: domain.TargetPath, Value: "/repo"}
	sc := domain.Scan{ID: "scan1", StartedAt: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC), FinishedAt: time.Date(2026, 10, 10, 9, 1, 0, 0, time.UTC),
		Profile: "standard", Targets: []domain.Target{tg}, TargetSetHash: domain.TargetSetHash([]domain.Target{tg}), ScopeHash: "abc",
		Consent: domain.ConsentRecord{Method: "local", By: "tester"}, Engines: []domain.EngineRun{{Name: "secrets", Status: "ok"}, {Name: "sca", Status: "skipped: offline"}},
		Partial: true, Posture: domain.PostureScore{Score: 55, Grade: "F", Partial: true}}
	if err := s.InsertScan(ctx, &sc); err != nil {
		t.Fatal(err)
	}
	w := s.NewWriter(ctx, sc.ID, nil)
	w.Add(domain.Finding{AssetKey: "repo:/repo", RuleID: "secret.aws-access-key", Engine: "secrets", Title: "AWS key <script>alert(1)</script>", Severity: domain.Critical, Confidence: domain.Firm,
		WhatItIs: "what", WhyItMatters: "why", HowToFix: "Revoke it", Location: "a.py:1#h", Risk: 55, Evidence: []domain.Evidence{{Kind: "file", Location: "a.py:1", Redacted: "AKIA************LE", Hash: "deadbeef"}}})
	w.Add(domain.Finding{AssetKey: "repo:/repo", RuleID: "x.low", Engine: "secrets", Title: "Low thing", Severity: domain.Low, Confidence: domain.Tentative, HowToFix: "fix low", Location: "b", Risk: 12, Status: domain.StatusAccepted})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(ctx, &sc); err != nil {
		t.Fatal(err)
	}
	return s, sc
}

func TestJSONReportSchema(t *testing.T) {
	s, sc := seed(t)
	prev := 80
	var buf bytes.Buffer
	if err := (&JSON{Meta: Meta{PreviousScore: &prev, Version: "test"}}).Write(context.Background(), s.Iterate(sc.ID), sc, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion string           `json:"schema_version"`
		Scan          domain.Scan      `json:"scan"`
		Assets        []domain.Asset   `json:"assets"`
		Findings      []domain.Finding `json:"findings"`
		PreviousScore int              `json:"previous_score"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if doc.SchemaVersion != SchemaVersion || doc.Scan.ID != "scan1" || doc.PreviousScore != 80 || doc.Scan.Posture.Score != 55 {
		t.Fatalf("header: %+v", doc)
	}
	if len(doc.Findings) != 2 || doc.Findings[0].Risk != 55 || len(doc.Findings[0].Evidence) != 1 || doc.Findings[0].Evidence[0].Redacted != "AKIA************LE" {
		t.Fatalf("findings: %+v", doc.Findings)
	}
	if len(doc.Assets) != 1 || doc.Assets[0].Key != "repo:/repo" {
		t.Fatalf("assets: %+v", doc.Assets)
	}
	for _, f := range doc.Findings {
		if f.CVEs == nil || f.References == nil || f.Evidence == nil {
			t.Fatalf("arrays must not be null: %+v", f)
		}
	}
}

func TestHTMLReport(t *testing.T) {
	s, sc := seed(t)
	var buf bytes.Buffer
	if err := (&HTML{Meta: Meta{Version: "test"}}).Write(context.Background(), s.Iterate(sc.ID), sc, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<!DOCTYPE html>", "55<span", "Grade F", "(partial)", "Fix these first", "Revoke it", "AKIA************LE", "skipped: offline", "Accepted / suppressed", "local by tester", "exploit data unavailable"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("hostile title not escaped")
	}
	if strings.Contains(out, "<script") || strings.Contains(out, "src=\"http") {
		t.Fatal("HTML must be self-contained with no scripts or external assets")
	}
}

// Finding 6: hostile finding text cannot inject Markdown links or images
// (tracking pixels, phishing links) into a PR comment. Every '[', ']' and
// '!' is escaped, in titles and in HowToFix alike.
func TestMarkdownNeutralisesLinkInjection(t *testing.T) {
	payload := "Open TCP port 22 (![](https://evil.example/pixel.png) [click to fix](https://evil.example/phish)) \\[x\\]"
	cell := mdCell(payload)
	unescaped := func(s string) bool {
		for i, c := range s {
			if (c == '[' || c == ']' || c == '!') && (i == 0 || s[i-1] != '\\') {
				return true
			}
		}
		return false
	}
	if unescaped(cell) {
		t.Fatalf("link syntax not neutralised: %s", cell)
	}
	if !strings.Contains(cell, `\[click to fix\](https://evil.example/phish)`) {
		t.Fatalf("expected escaped text to survive: %s", cell)
	}
	// Input backslashes are doubled so they cannot cancel our escapes.
	if !strings.Contains(cell, `\\\[x\\\]`) {
		t.Fatalf("backslash handling: %s", cell)
	}

	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	tg := domain.Target{Raw: "h", Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"}
	sc := domain.Scan{ID: "scan-md", StartedAt: time.Now(), Profile: "standard", Targets: []domain.Target{tg}, TargetSetHash: domain.TargetSetHash([]domain.Target{tg}),
		Engines: []domain.EngineRun{{Name: "netscan", Status: "ok"}}}
	if err := s.InsertScan(ctx, &sc); err != nil {
		t.Fatal(err)
	}
	w := s.NewWriter(ctx, sc.ID, nil)
	if err := w.Add(domain.Finding{AssetKey: "host:10.0.0.5", RuleID: "net.open-port", Engine: "netscan", Title: payload, HowToFix: payload, Severity: domain.Low, Location: "10.0.0.5:22#" + payload, Risk: 30}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := (&Markdown{}).Write(ctx, s.Iterate(sc.ID), sc, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "![](https://evil.example") || strings.Contains(out, " [click to fix](https://evil.example") {
		t.Fatalf("payload rendered as link/image:\n%s", out)
	}
	// The payload appears in the title (table + fix list), HowToFix and the
	// location; every occurrence must be the escaped form.
	if n := strings.Count(out, cell); n < 3 {
		t.Fatalf("expected the escaped payload at least 3 times (title, fix, location), found %d:\n%s", n, out)
	}
	if strings.Count(out, "evil.example") != strings.Count(out, `\](https://evil.example`) {
		t.Fatalf("an evil.example reference is not preceded by an escaped bracket:\n%s", out)
	}
}

func TestParseFormats(t *testing.T) {
	reg := Registry(Meta{})
	rs, err := ParseFormats("html, json", reg)
	if err != nil || len(rs) != 2 {
		t.Fatal(err)
	}
	if _, err := ParseFormats("pdf", reg); err == nil || !strings.Contains(err.Error(), "available") {
		t.Fatalf("unknown format should list available: %v", err)
	}
	if _, err := ParseFormats("", reg); err == nil {
		t.Fatal("empty formats accepted")
	}
}

func TestWriteAll(t *testing.T) {
	s, sc := seed(t)
	dir := t.TempDir()
	rs, _ := ParseFormats("html,json", Registry(Meta{}))
	paths, err := WriteAll(context.Background(), s, sc, rs, dir)
	if err != nil || len(paths) != 2 || !strings.HasSuffix(paths[0], "report.html") || !strings.HasSuffix(paths[1], "report.json") {
		t.Fatalf("%v %v", paths, err)
	}
	// Finding 10: a report file name that is a symlink is refused, never
	// followed and truncated.
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	dir2 := t.TempDir()
	os.Symlink(victim, filepath.Join(dir2, "report.json"))
	if _, err := WriteAll(context.Background(), s, sc, rs, dir2); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlinked report path accepted: %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", b)
	}
}
