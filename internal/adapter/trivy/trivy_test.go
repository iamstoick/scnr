package trivy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gerald/scnr/internal/adapter"
	"github.com/gerald/scnr/internal/adapter/adaptertest"
	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/engine/image"
	"github.com/gerald/scnr/internal/safety"
)

func opts(t *testing.T, online bool) engine.Options {
	t.Helper()
	p, _ := engine.ProfileByName("standard")
	return engine.Options{Profile: p, Scratch: t.TempDir(), Redactor: safety.NewRedactor(), Online: online}
}

func parseFixture(t *testing.T, version string, tg domain.Target) (map[string]domain.Finding, error) {
	t.Helper()
	f, err := os.Open(filepath.Join(adaptertest.FixtureDir(t, "trivy", version), "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	a.Root, a.AssetKey = tg.Value, tg.AssetKey()
	out := map[string]domain.Finding{}
	err = a.Parse(f, func(fd domain.Finding) error { out[fd.RuleID] = fd; return nil })
	return out, err
}

func TestParseFixtures(t *testing.T) {
	repo := domain.Target{Type: domain.TargetPath, Value: "/repo/root"}
	got, err := parseFixture(t, "0.58.0", repo)
	if err != nil || len(got) != 3 {
		t.Fatalf("0.58.0: %d findings, err %v: %v", len(got), err, got)
	}
	// Shared SCA scheme: same rule ID and location as the native engine.
	v := got["sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20"]
	if v.Location != "package-lock.json" || v.Severity != domain.High || v.CVSS == nil || v.CVSS.Score != 7.4 || v.CWE != "CWE-770" || !strings.Contains(v.HowToFix, "4.17.21") || v.AssetKey != "repo:/repo/root" {
		t.Fatalf("%+v", v)
	}
	if v.Fingerprint != domain.Fingerprint(v.RuleID, "repo:/repo/root", "package-lock.json:7") {
		t.Fatal("fingerprint must ignore lockfile line numbers so native/trivy/grype dedupe")
	}
	if !strings.HasPrefix(v.Evidence[0].Redacted, "trivy: ") {
		t.Fatalf("evidence should name the tool: %q", v.Evidence[0].Redacted)
	}
	m := got["trivy:DS002"]
	if m.Severity != domain.High || m.Location != "Dockerfile" || !strings.Contains(m.HowToFix, "USER") || len(m.References) != 2 {
		t.Fatalf("%+v", m)
	}
	s := got["secret:aws-access-key-id"]
	if s.Severity != domain.Critical || s.Location != "config/settings.py:3" || s.CWE != "CWE-798" || strings.Contains(s.Evidence[0].Redacted, "AKIA") {
		t.Fatalf("%+v", s)
	}

	img := domain.Target{Type: domain.TargetImage, Value: "/tmp/alpine-small.tar", Labels: map[string]string{image.SourceLabel: image.SourceDockerTar}}
	got, err = parseFixture(t, "0.65.0", img)
	if err == nil || !strings.Contains(err.Error(), "2 element(s)") {
		t.Fatalf("hostile results must be reported: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("0.65.0: %v", got)
	}
	// OS package: qualifiers dropped from the PURL, location is the apk db.
	os := got["sca.osv.CVE-2023-5363@pkg:apk/alpine/libcrypto3@3.1.4-r1"]
	if os.Location != "lib/apk/db/installed" || os.AssetKey != "image:/tmp/alpine-small.tar" || os.CVSS.Score != 7.5 || os.CWE != "CWE-325" {
		t.Fatalf("%+v", os)
	}
	l := got["sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20"]
	if l.Location != "app/package-lock.json" || strings.ContainsAny(l.Title, "\x07\x1b") || strings.Contains(l.WhatItIs, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
		t.Fatalf("control chars or token leaked: %+v", l)
	}
	for id := range got {
		if strings.Contains(id, "9999") || strings.Contains(id, "..") || strings.Contains(id, "CVE-2020-0001") {
			t.Fatalf("hostile element accepted: %s", id)
		}
	}
}

func TestArgs(t *testing.T) {
	a, _ := New()
	o := opts(t, true)
	args, err := a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, o)
	if err != nil {
		t.Fatal(err)
	}
	j := " " + strings.Join(args, " ") + " "
	// Finding 6: --offline-scan is unconditional so a scanned pom.xml or
	// module source can never drive trivy to an endpoint of its choosing.
	for _, want := range []string{" fs ", " --format json ", " --scanners vuln,misconfig,secret ", " --disable-telemetry ", " --skip-version-check ", " --quiet ", " --offline-scan ", " --tf-exclude-downloaded-modules ", " -- /repo "} {
		if !strings.Contains(j, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	if strings.Contains(j, "--skip-db-update") {
		t.Fatal("online scan should allow the DB download (that is the opt-in)")
	}
	if err := adapter.CheckForbidden(args); err != nil {
		t.Fatal(err)
	}
	// Offline: no DB or check-bundle downloads.
	args, _ = a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, opts(t, false))
	j = " " + strings.Join(args, " ") + " "
	for _, want := range []string{" --skip-db-update ", " --skip-java-db-update ", " --skip-check-update ", " --offline-scan "} {
		if !strings.Contains(j, want) {
			t.Errorf("offline missing %q in %v", want, args)
		}
	}
	// Local image archive: --input; registry reference: skipped, never pulled.
	args, err = a.Args(domain.Target{Type: domain.TargetImage, Value: "/tmp/img.tar", Labels: map[string]string{image.SourceLabel: image.SourceDockerTar}}, o)
	if err != nil || !strings.Contains(" "+strings.Join(args, " ")+" ", " image --input /tmp/img.tar ") {
		t.Fatalf("%v %v", args, err)
	}
	var skip *engine.SkipError
	if _, err := a.Args(domain.Target{Type: domain.TargetImage, Value: "alpine:3.18"}, o); !errors.As(err, &skip) || !strings.Contains(skip.Reason, "docker save") {
		t.Fatalf("registry ref must skip: %v", err)
	}
	for _, bad := range [][]string{{"--server", "http://x"}, {"--token", "t"}, {"--token-header", "x"}} {
		if err := adapter.CheckForbidden(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestRunWithFakeBinary(t *testing.T) {
	fixture := filepath.Join(adaptertest.FixtureDir(t, "trivy", "0.58.0"), "results.json")
	argvPath := adaptertest.Install(t, "trivy", "--version", "Version: 0.58.0\nVulnerability DB:\n  Version: 2", copyToOutput(fixture))
	a, _ := New()
	o := opts(t, true)
	root := t.TempDir()
	n := 0
	err := a.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: root}, o, func(f domain.Finding) error { n++; return nil })
	if err != nil || n != 3 || a.Version() != "0.58.0" {
		t.Fatalf("n=%d version=%q err=%v", n, a.Version(), err)
	}
	argv := adaptertest.Argv(t, argvPath)
	if j := " " + strings.Join(argv, " ") + " "; !strings.Contains(j, " --disable-telemetry ") || !strings.Contains(j, " -- "+root+" ") {
		t.Fatalf("argv %v", argv)
	}
	adaptertest.Install(t, "trivy", "--version", "Version: 0.45.0", "")
	b, _ := New()
	var skip *engine.SkipError
	if err := b.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: root}, o, nil); !errors.As(err, &skip) || !strings.Contains(skip.Reason, "0.58.0") {
		t.Fatalf("old trivy should skip naming the minimum: %v", err)
	}
	adaptertest.Hide(t)
	c, _ := New()
	if err := c.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: root}, o, nil); !errors.As(err, &skip) {
		t.Fatalf("missing trivy should skip: %v", err)
	}
}

func copyToOutput(file string) string {
	return `OUT2=''; prev=''; for a in "$@"; do if [ "$prev" = "--output" ]; then OUT2="$a"; fi; prev="$a"; done; : > "$OUT2"; while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line" >> "$OUT2"; done < '` + file + `'`
}
