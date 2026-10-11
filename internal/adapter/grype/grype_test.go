package grype

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
	"github.com/iamstoick/scnr/internal/engine/image"
	"github.com/iamstoick/scnr/internal/safety"
)

func opts(t *testing.T, online bool) engine.Options {
	t.Helper()
	p, _ := engine.ProfileByName("standard")
	return engine.Options{Profile: p, Scratch: t.TempDir(), Redactor: safety.NewRedactor(), Online: online}
}

func parseFixture(t *testing.T, version string, tg domain.Target) (map[string]domain.Finding, error) {
	t.Helper()
	f, err := os.Open(filepath.Join(adaptertest.FixtureDir(t, "grype", version), "results.json"))
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
	got, err := parseFixture(t, "0.80.0", repo)
	if err != nil || len(got) != 1 {
		t.Fatalf("0.80.0: %v %v", got, err)
	}
	// GHSA primary with a CVE in relatedVulnerabilities -> CVE rule ID, same
	// as native SCA and trivy; "/package-lock.json" -> "package-lock.json".
	v := got["sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20"]
	if v.Location != "package-lock.json" || v.Severity != domain.High || v.CVSS == nil || v.CVSS.Score != 7.4 || !strings.Contains(v.HowToFix, "4.17.21") || len(v.CVEs) != 1 || !strings.HasPrefix(v.Evidence[0].Redacted, "grype: ") {
		t.Fatalf("%+v", v)
	}
	if len(v.References) != 3 {
		t.Fatalf("refs %v", v.References)
	}

	img := domain.Target{Type: domain.TargetImage, Value: "/tmp/alpine-small.tar", Labels: map[string]string{image.SourceLabel: image.SourceDockerTar}}
	got, err = parseFixture(t, "0.95.0", img)
	if err == nil || !strings.Contains(err.Error(), "3 element(s)") {
		t.Fatalf("hostile matches must be reported: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("0.95.0: %v", got)
	}
	os := got["sca.osv.CVE-2023-5363@pkg:apk/alpine/libcrypto3@3.1.4-r1"]
	if os.Location != "lib/apk/db/installed" || os.CVSS == nil || os.CVSS.Score != 7.5 || !strings.Contains(os.HowToFix, "3.1.4-r2") {
		t.Fatalf("%+v", os)
	}
	l := got["sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20"]
	if l.Location != "app/package-lock.json" || strings.Contains(l.WhatItIs, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0") {
		t.Fatalf("token leaked or wrong location: %+v", l)
	}
	// No PURL: ecosystem fallback from the artifact type, control chars stripped.
	z := got["sca.osv.CVE-2024-0003@pkg:apk/alpine/zlib@1.2.13-r1"]
	if z.Severity != domain.Low || strings.ContainsAny(z.WhatItIs, "\x00\x01") || !strings.Contains(z.HowToFix, "No fixed version") {
		t.Fatalf("%+v", z)
	}
	for id := range got {
		if strings.Contains(id, "CVE-2024-0001") || strings.Contains(id, "CVE-2024-0002") {
			t.Fatalf("hostile element accepted: %s", id)
		}
	}
}

func TestArgsAndEnv(t *testing.T) {
	a, _ := New()
	o := opts(t, true)
	args, err := a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, o)
	if err != nil {
		t.Fatal(err)
	}
	if j := " " + strings.Join(args, " ") + " "; !strings.Contains(j, " dir:/repo ") || !strings.Contains(j, " -o json ") || !strings.Contains(j, " --file "+filepath.Join(o.Scratch, outputFile)+" ") || !strings.Contains(j, " -q ") {
		t.Fatalf("%v", args)
	}
	if env := strings.Join(a.Env(), " "); !strings.Contains(env, "GRYPE_CHECK_FOR_APP_UPDATE=false") || !strings.Contains(env, "GRYPE_DB_AUTO_UPDATE=true") {
		t.Fatalf("online env %v", a.Env())
	}
	a.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, opts(t, false))
	if env := strings.Join(a.Env(), " "); !strings.Contains(env, "GRYPE_DB_AUTO_UPDATE=false") {
		t.Fatalf("offline env %v", a.Env())
	}
	if err := adapter.CheckForbidden(args); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		labels map[string]string
		want   string
	}{
		{map[string]string{image.SourceLabel: image.SourceDockerTar}, "docker-archive:/tmp/i"},
		{map[string]string{image.SourceLabel: image.SourceOCILayout}, "oci-dir:/tmp/i"},
	} {
		args, err := a.Args(domain.Target{Type: domain.TargetImage, Value: "/tmp/i", Labels: c.labels}, o)
		if err != nil || args[0] != c.want {
			t.Fatalf("%v %v", args, err)
		}
	}
	var skip *engine.SkipError
	if _, err := a.Args(domain.Target{Type: domain.TargetImage, Value: "alpine:3.18"}, o); !errors.As(err, &skip) {
		t.Fatalf("registry ref must skip: %v", err)
	}
	if _, err := a.Args(domain.Target{Type: domain.TargetPath, Value: "-q"}, o); err == nil {
		t.Fatal("flag-shaped path accepted")
	}
	if err := adapter.CheckForbidden([]string{"dir:/x", "--only-fixed"}); err == nil {
		t.Fatal("--only-fixed accepted")
	}
}

func TestRunWithFakeBinary(t *testing.T) {
	fixture := filepath.Join(adaptertest.FixtureDir(t, "grype", "0.80.0"), "results.json")
	// The fake records its environment too so the DB switch can be asserted.
	argvPath := adaptertest.Install(t, "grype", "--version", "grype 0.80.0", `printf '%s\n' "ENV GRYPE_DB_AUTO_UPDATE=$GRYPE_DB_AUTO_UPDATE GRYPE_CHECK_FOR_APP_UPDATE=$GRYPE_CHECK_FOR_APP_UPDATE" >> '`+t.TempDir()+`/env'; `+copyToFile(fixture))
	a, _ := New()
	o := opts(t, false)
	root := t.TempDir()
	n := 0
	err := a.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: root}, o, func(f domain.Finding) error { n++; return nil })
	if err != nil || n != 1 || a.Version() != "0.80.0" {
		t.Fatalf("n=%d version=%q err=%v", n, a.Version(), err)
	}
	argv := adaptertest.Argv(t, argvPath)
	if argv[0] != "dir:"+root {
		t.Fatalf("argv %v", argv)
	}
	adaptertest.Hide(t)
	b, _ := New()
	var skip *engine.SkipError
	if err := b.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: root}, o, nil); !errors.As(err, &skip) {
		t.Fatalf("missing grype should skip: %v", err)
	}
}

// TestChildEnvIsFixed runs the fake through Base.Exec and checks the
// environment it saw: only PATH/HOME/TMPDIR pass through, plus our switches.
func TestChildEnvIsFixed(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "env")
	adaptertest.Install(t, "grype", "--version", "grype 0.80.0", `env > '`+envFile+`'; echo '{"matches":[]}' > "$(for a in "$@"; do :; done; prev=''; for a in "$@"; do if [ "$prev" = "--file" ]; then printf '%s' "$a"; fi; prev="$a"; done)"`)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
	a, _ := New()
	o := opts(t, false)
	if err := a.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: t.TempDir()}, o, nil); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	s := string(env)
	if strings.Contains(s, "must-not-leak") || !strings.Contains(s, "GRYPE_DB_AUTO_UPDATE=false") || !strings.Contains(s, "GRYPE_CHECK_FOR_APP_UPDATE=false") {
		t.Fatalf("child env:\n%s", s)
	}
}

func copyToFile(file string) string {
	return `OUT2=''; prev=''; for a in "$@"; do if [ "$prev" = "--file" ]; then OUT2="$a"; fi; prev="$a"; done; : > "$OUT2"; while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line" >> "$OUT2"; done < '` + file + `'`
}
